"""tests/unit/core/test_server.py -- accept loop, thread cap (503), shutdown, no gauge drift."""
import socket
import struct
import threading
import time

from tests.conftest import HttpOrigin, recv_all, wait_for


def get_request(port):
    return (f"GET http://127.0.0.1:{port}/ HTTP/1.1\r\nHost: x\r\n\r\n").encode()


def test_server_binds_a_real_port_when_asked_for_zero(make_proxy):
    proxy = make_proxy()
    assert proxy.port > 0


def test_serves_a_request_end_to_end(make_proxy, http_origin):
    proxy = make_proxy()
    s = proxy.connect()
    s.sendall(get_request(http_origin.port))
    reply = recv_all(s)
    s.close()
    assert b"200 OK" in reply and reply.endswith(b"origin ok")


def test_active_conns_returns_to_zero_after_many_requests(make_proxy, http_origin):
    proxy = make_proxy()
    for _ in range(25):
        s = proxy.connect()
        s.sendall(get_request(http_origin.port))
        recv_all(s)
        s.close()
    assert wait_for(lambda: proxy.active() == 0)
    assert len(proxy.logger.of("conn_open")) == len(proxy.logger.of("conn_close")) == 25


def test_active_conns_zero_after_clients_that_just_connect_and_leave(make_proxy):
    proxy = make_proxy()
    for _ in range(10):
        proxy.connect().close()
    assert wait_for(lambda: proxy.active() == 0)


def test_active_conns_zero_after_client_reset_mid_request(make_proxy):
    proxy = make_proxy()
    s = proxy.connect()
    s.sendall(b"GET http://127.0.0.1:9/ HTTP/1.1\r\nHo")      # half a head, then slam shut
    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))   # send RST
    s.close()
    assert wait_for(lambda: proxy.active() == 0)
    assert wait_for(lambda: len(proxy.logger.of("conn_close")) == 1)


def test_thread_cap_gives_503_and_does_not_touch_the_gauge(make_proxy):
    slow = HttpOrigin(delay=1.0)                             # holds each request for 1 s
    proxy = make_proxy(max_threads=2)
    busy = []
    for _ in range(2):                                       # fill both slots
        s = proxy.connect()
        s.sendall(get_request(slow.port))
        busy.append(s)
    assert wait_for(lambda: proxy.active() == 2)

    extra = proxy.connect()                                  # third client: over the cap
    extra.sendall(get_request(slow.port))
    reply = recv_all(extra)
    extra.close()
    assert reply.startswith(b"HTTP/1.1 503"), reply[:40]
    assert b"Retry-After" in reply
    assert proxy.active() == 2, "a rejected client must not change active_conns"
    assert slow.accepted <= 2, "a rejected client must not reach the origin"

    for s in busy:                                           # the two real ones still finish
        assert b"origin ok" in recv_all(s)
        s.close()
    assert wait_for(lambda: proxy.active() == 0)
    pool_errors = [e for e in proxy.logger.of("error") if e["error"] == "PoolFull"]
    assert len(pool_errors) >= 1
    slow.close()


def test_slot_is_released_so_new_clients_work_after_the_cap_clears(make_proxy, http_origin):
    proxy = make_proxy(max_threads=1)
    for _ in range(5):                                       # sequential; one slot is enough
        s = proxy.connect()
        s.sendall(get_request(http_origin.port))
        assert b"origin ok" in recv_all(s)
        s.close()
        assert wait_for(lambda: proxy.active() == 0)


def test_parallel_clients_all_succeed_and_gauge_is_zero(make_proxy, http_origin):
    proxy = make_proxy()
    results = []

    def client():
        s = proxy.connect()
        s.sendall(get_request(http_origin.port))
        results.append(b"origin ok" in recv_all(s))
        s.close()

    threads = [threading.Thread(target=client) for _ in range(40)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(10)
    assert results.count(True) == 40
    assert wait_for(lambda: proxy.active() == 0)
    snap = proxy.stats.snapshot()
    assert snap["requests_total"] == 40


def test_shutdown_stops_accepting_and_returns(make_proxy):
    proxy = make_proxy()
    proxy.server.shutdown(timeout=1)
    proxy.thread.join(3)
    assert not proxy.thread.is_alive()
    try:
        socket.create_connection(("127.0.0.1", proxy.port), timeout=1).close()
        refused = False
    except OSError:
        refused = True
    assert refused


def test_shutdown_force_closes_stuck_sessions(make_proxy):
    slow = HttpOrigin(delay=5.0)
    proxy = make_proxy()
    s = proxy.connect()
    s.sendall(get_request(slow.port))
    assert wait_for(lambda: proxy.active() == 1)
    started = time.monotonic()
    proxy.server.shutdown(timeout=0.3)
    assert time.monotonic() - started < 2
    assert wait_for(lambda: proxy.active() == 0)             # force-close ran the finally block
    s.close()
    slow.close()


def test_two_proxies_cannot_share_a_port(make_proxy):
    proxy = make_proxy()
    try:
        make_proxy(port=proxy.port)
        clash = False
    except OSError:
        clash = True
    assert clash


def test_flood_over_the_cap_is_rejected_without_hurting_the_busy_slot(make_proxy):
    """60 extra clients hit a full proxy: the one real session must be unaffected."""
    slow = HttpOrigin(delay=1.0)
    proxy = make_proxy(max_threads=1)
    real = proxy.connect()
    real.sendall(get_request(slow.port))
    assert wait_for(lambda: proxy.active() == 1)

    got_503 = 0
    for _ in range(60):
        extra = proxy.connect()
        extra.sendall(get_request(slow.port))
        if recv_all(extra).startswith(b"HTTP/1.1 503"):
            got_503 += 1
        extra.close()
    assert got_503 >= 30, f"only {got_503}/60 clients saw the 503"   # a few hard drops are ok
    assert proxy.active() == 1                                       # gauge untouched by rejects
    assert b"origin ok" in recv_all(real)                            # real client still served
    real.close()
    assert wait_for(lambda: proxy.active() == 0)
    slow.close()