"""tests/integration/test_proxy_e2e.py -- the whole proxy over real sockets.

Part A uses stubs (runs on feat/core alone).
Part B uses the real obs + control modules and is skipped until those branches are merged.
"""
import json
import socket
import struct

import pytest

from tests.conftest import DenyAuth, DenyFilter, recv_all, wait_for


def get(port):
    return f"GET http://127.0.0.1:{port}/ HTTP/1.1\r\nHost: x\r\n\r\n".encode()


def connect_req(port):
    return f"CONNECT 127.0.0.1:{port} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n".encode()


# ============================================================ Part A: core + stubs
def test_connect_tunnel_echoes_and_counts(make_proxy, echo_origin):
    proxy = make_proxy()
    s = proxy.connect()
    s.settimeout(3)
    s.sendall(connect_req(echo_origin.port))
    assert s.recv(100).startswith(b"HTTP/1.1 200")
    s.sendall(b"ping-through-tunnel")
    assert s.recv(100) == b"ping-through-tunnel"
    s.close()
    assert wait_for(lambda: proxy.active() == 0)
    snap = proxy.stats.snapshot()
    assert snap["bytes_up"] == 19 and snap["bytes_down"] == 19
    close = proxy.logger.of("conn_close")[0]
    assert (close["bytes_up"], close["bytes_down"]) == (19, 19)   # same totals in log and stats


def test_tunnel_killed_mid_relay_still_decrements_and_empties_registry(make_proxy, echo_origin):
    """The viva question: finally runs even when the client dies with a RST mid-tunnel."""
    proxy = make_proxy()
    s = proxy.connect()
    s.settimeout(3)
    s.sendall(connect_req(echo_origin.port))
    s.recv(100)
    s.sendall(b"some bytes")
    s.recv(100)
    assert proxy.server.active_tunnels() != []
    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    s.close()                                                    # RST, no goodbye
    assert wait_for(lambda: proxy.active() == 0)
    assert wait_for(lambda: proxy.server.active_tunnels() == [])
    assert len(proxy.logger.of("conn_close")) == 1
    assert len(proxy.logger.of("tunnel_close")) == 1


def test_blocked_connect_gets_403_and_never_reaches_the_site(make_proxy, echo_origin):
    proxy = make_proxy(filt=DenyFilter(deny_host="127.0.0.1"))
    s = proxy.connect()
    s.sendall(connect_req(echo_origin.port))
    assert recv_all(s).startswith(b"HTTP/1.1 403")
    assert echo_origin.accepted == 0
    blocked = proxy.logger.of("req_blocked")[0]
    assert blocked["method"] == "CONNECT"
    assert wait_for(lambda: proxy.active() == 0)


def test_ip_guard_blocks_connect_after_dns(make_proxy, echo_origin):
    proxy = make_proxy(filt=DenyFilter(deny_ip="127.0.0.1"))
    s = proxy.connect()
    s.sendall(connect_req(echo_origin.port))
    assert recv_all(s).startswith(b"HTTP/1.1 403")
    assert echo_origin.accepted == 0
    assert proxy.logger.of("req_blocked")[0]["path"] is None     # CONNECT block: path=None
    assert proxy.stats.snapshot()["requests_blocked"] == 1


def test_proxy_refuses_to_connect_to_itself(make_proxy):
    proxy = make_proxy()
    s = proxy.connect()
    s.sendall(connect_req(proxy.port))                           # CONNECT to own port
    assert recv_all(s).startswith(b"HTTP/1.1 403")
    assert wait_for(lambda: proxy.active() == 0)


def test_unauthenticated_client_gets_407_no_upstream(make_proxy, http_origin):
    proxy = make_proxy(auth=DenyAuth())
    s = proxy.connect()
    s.sendall(get(http_origin.port))
    assert recv_all(s).startswith(b"HTTP/1.1 407")
    assert http_origin.accepted == 0


def test_one_bad_client_does_not_hurt_another(make_proxy, http_origin):
    proxy = make_proxy()
    bad = proxy.connect()
    bad.sendall(b"garbage\r\n\r\n")
    good = proxy.connect()
    good.sendall(get(http_origin.port))
    assert b"origin ok" in recv_all(good)
    assert recv_all(bad).startswith(b"HTTP/1.1 400")
    assert wait_for(lambda: proxy.active() == 0)


def test_sent_equals_logged_equals_counted(make_proxy, http_origin):
    proxy = make_proxy()
    for _ in range(15):
        s = proxy.connect()
        s.sendall(get(http_origin.port))
        recv_all(s)
        s.close()
    assert wait_for(lambda: len(proxy.logger.of("conn_close")) == 15)
    assert len(proxy.logger.of("req_forward")) == 15
    assert proxy.stats.snapshot()["requests_total"] == 15
    log_up = sum(e["bytes_up"] for e in proxy.logger.of("conn_close"))
    log_down = sum(e["bytes_down"] for e in proxy.logger.of("conn_close"))
    snap = proxy.stats.snapshot()
    assert (snap["bytes_up"], snap["bytes_down"]) == (log_up, log_down)


def test_event_fields_match_the_contract(make_proxy, http_origin):
    """Field names the dashboard and Abdur's tests rely on (PRD 6.4)."""
    proxy = make_proxy()
    s = proxy.connect()
    s.sendall(get(http_origin.port))
    recv_all(s)
    s.close()
    assert wait_for(lambda: len(proxy.logger.of("conn_close")) == 1)
    assert {"conn_id", "client_ip", "client_port"} <= set(proxy.logger.of("conn_open")[0])
    assert {"conn_id", "method", "host", "port", "path", "status", "duration_ms"} \
        <= set(proxy.logger.of("req_forward")[0])
    assert {"conn_id", "duration_ms", "bytes_up", "bytes_down", "outcome"} \
        <= set(proxy.logger.of("conn_close")[0])
    from proxy.interfaces import EVENT_KINDS
    assert {e["kind"] for e in proxy.logger.events} <= set(EVENT_KINDS)


# ============================================================ Part B: real obs + control
try:
    from proxy.obs import build_logger, build_stats
    from proxy.control import build_auth, build_filter
    from proxy.control.config import load_config
    REAL = True
except ImportError:
    REAL = False

needs_real = pytest.mark.skipif(not REAL, reason="feat/obs and feat/control not merged yet")


@needs_real
def test_real_modules_log_valid_json_and_stats_match(tmp_path, http_origin):
    import threading
    from proxy.core import ProxyServer
    probe = socket.socket()                                       # real config rejects port 0
    probe.bind(("127.0.0.1", 0))
    free_port = probe.getsockname()[1]
    probe.close()
    cfg_file = tmp_path / "cfg.json"
    cfg_file.write_text(json.dumps({
        "proxy": {"host": "127.0.0.1", "port": free_port, "max_threads": 100},
        "filter": {"mode": "denylist", "deny_domains": [],
                   "block_private_ips": True, "private_allow": ["127.0.0.1:%d" % http_origin.port]},
        "auth": {"enabled": False},
        "logging": {"file": str(tmp_path / "proxy.jsonl")},
    }))
    config = load_config(["--config", str(cfg_file)])
    stats, logger = build_stats(), None
    logger = build_logger(config, stats)
    server = ProxyServer(config, build_filter(config), build_auth(config), logger, stats)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        for _ in range(20):
            s = socket.create_connection(("127.0.0.1", server.port), timeout=5)
            s.sendall(get(http_origin.port))
            recv_all(s)
            s.close()
        assert wait_for(lambda: stats.snapshot()["active_conns"] == 0)
        snap = stats.snapshot()
        assert snap["requests_total"] == 20 and set(snap) >= {
            "requests_total", "requests_blocked", "active_conns", "bytes_up",
            "bytes_down", "errors"}
    finally:
        server.shutdown(timeout=2)
        logger.flush()
        logger.close()
    lines = (tmp_path / "proxy.jsonl").read_text().splitlines()
    events = [json.loads(line) for line in lines]                 # every line must parse
    assert sum(e["kind"] == "conn_open" for e in events) == 20
    assert sum(e["kind"] == "conn_close" for e in events) == 20
    assert logger.dropped == 0
