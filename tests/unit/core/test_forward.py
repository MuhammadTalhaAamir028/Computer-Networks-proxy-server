"""tests/unit/core/test_forward.py -- plain HTTP forwarding: rewriting, bodies, errors, bytes."""
import socket
import threading

import pytest

from proxy.core.errors import HttpError
from proxy.core.forward import build_upstream_head, forward_http
from proxy.core.httpparse import parse_head
from proxy.stubs import MemoryStats
from tests.conftest import recv_all


def req_from(text: str, leftover: bytes = b""):
    req = parse_head(text.encode().split(b"\r\n\r\n")[0] + b"\r\n\r\n")
    req.leftover = leftover
    return req


# ------------------------------------------------------------ request rewriting (pure)
def test_request_becomes_origin_form_with_host_and_connection_close():
    req = req_from("GET http://example.com:8080/a?x=1 HTTP/1.1\r\nHost: wrong\r\n\r\n")
    head = build_upstream_head(req).decode()
    assert head.startswith("GET /a?x=1 HTTP/1.1\r\n")
    assert "Host: example.com:8080\r\n" in head          # rebuilt from the URL, not the client
    assert "Host: wrong" not in head
    assert head.endswith("Connection: close\r\n\r\n")


def test_default_port_80_is_not_written_in_host():
    head = build_upstream_head(req_from("GET http://example.com/ HTTP/1.1\r\nHost: x\r\n\r\n"))
    assert b"Host: example.com\r\n" in head


def test_proxy_credentials_and_hop_headers_never_reach_the_website():
    req = req_from("GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n"
                   "Proxy-Authorization: Basic c2VjcmV0\r\nProxy-Connection: keep-alive\r\n"
                   "Keep-Alive: 5\r\nUser-Agent: t\r\n\r\n")
    head = build_upstream_head(req).decode().lower()
    assert "proxy-authorization" not in head and "c2vjcmv0" not in head
    assert "proxy-connection" not in head and "keep-alive" not in head
    assert "user-agent: t" in head                        # normal headers survive


def test_headers_named_in_connection_are_stripped_too():
    req = req_from("GET http://example.com/ HTTP/1.1\r\nHost: x\r\n"
                   "Connection: X-Secret\r\nX-Secret: 1\r\nX-Keep: 2\r\n\r\n")
    head = build_upstream_head(req).decode()
    assert "X-Secret" not in head and "x-secret" not in head
    assert "x-keep: 2" in head.lower()


# ------------------------------------------------------------ forward_http with sockets
def run_forward(req, site_reply: bytes = b"", client_body: bytes = b"", site_close_early=False,
                client_hangs_up=False):
    """Run forward_http. Returns (result_or_exc, bytes_seen_by_site, bytes_seen_by_client, stats)."""
    stats = MemoryStats()
    proxy_client, client_side = socket.socketpair()
    proxy_up, site_side = socket.socketpair()
    for s in (proxy_client, proxy_up, client_side, site_side):
        s.settimeout(3)
    seen = {}

    def site():
        data = b""
        try:
            while b"\r\n\r\n" not in data:
                chunk = site_side.recv(4096)
                if not chunk:
                    break
                data += chunk
            if not site_close_early:
                length = 0
                for line in data.split(b"\r\n\r\n")[0].split(b"\r\n"):
                    if line.lower().startswith(b"content-length:"):
                        length = int(line.split(b":")[1])
                body = data.partition(b"\r\n\r\n")[2]
                while len(body) < length:
                    more = site_side.recv(65536)
                    if not more:                            # proxy gave up and closed
                        break
                    body += more
                data = data.partition(b"\r\n\r\n")[0] + b"\r\n\r\n" + body
                site_side.sendall(site_reply)
        except OSError:
            pass
        finally:
            seen["data"] = data
            site_side.close()

    t = threading.Thread(target=site, daemon=True)
    t.start()
    got = {}
    reader = threading.Thread(target=lambda: got.setdefault("reply", recv_all(client_side)),
                              daemon=True)
    reader.start()                                          # drain replies so big ones never block
    if client_body:
        client_side.sendall(client_body)
    if client_hangs_up:
        client_side.shutdown(socket.SHUT_WR)                # client says 'no more bytes'
    try:
        out = forward_http(proxy_client, proxy_up, req, stats)
    except HttpError as exc:
        out = exc
    proxy_client.close()
    proxy_up.close()
    t.join(3)
    reader.join(3)
    return out, seen.get("data", b""), got.get("reply", b""), stats


def test_get_roundtrip_and_hop_by_hop_response_headers_removed():
    req = req_from("GET http://h/ HTTP/1.1\r\nHost: h\r\n\r\n")
    site = (b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nKeep-Alive: timeout=5\r\n"
            b"Connection: close\r\n\r\nhi")
    res, seen, reply, _ = run_forward(req, site)
    assert res.status == 200 and res.started and res.error is None
    assert reply.startswith(b"HTTP/1.1 200 OK") and reply.endswith(b"hi")
    assert b"Keep-Alive" not in reply
    assert reply.count(b"Connection: close") == 1
    assert seen.startswith(b"GET / HTTP/1.1")


def test_status_codes_pass_through_unchanged():
    req = req_from("GET http://h/x HTTP/1.1\r\nHost: h\r\n\r\n")
    res, _, reply, _ = run_forward(req, b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
    assert res.status == 404 and reply.startswith(b"HTTP/1.1 404")


def test_post_body_is_streamed_with_leftover_first():
    body = b"a=1&b=2&c=three"
    head = (f"POST http://h/p HTTP/1.1\r\nHost: h\r\nContent-Length: {len(body)}\r\n\r\n")
    req = req_from(head, leftover=body[:5])                 # first 5 bytes arrived with the head
    res, seen, _, _ = run_forward(req, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
                                  client_body=body[5:])
    assert res.status == 200
    assert seen.endswith(b"\r\n\r\n" + body)                # the website got all of it, in order


def test_bytes_are_counted_exactly_once():
    body = b"x" * 1000
    head = f"POST http://h/p HTTP/1.1\r\nHost: h\r\nContent-Length: 1000\r\n\r\n"
    req = req_from(head)
    site = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
    res, seen, reply, stats = run_forward(req, site, client_body=body)
    assert res.bytes_up == len(seen)                        # what the site saw == counted up
    assert res.bytes_down == len(reply)                     # what the client saw == counted down
    snap = stats.snapshot()
    assert snap["bytes_up"] == res.bytes_up and snap["bytes_down"] == res.bytes_down


def test_large_response_is_counted_exactly():
    big = b"B" * 200_000                                    # larger than FLUSH_BYTES
    site = b"HTTP/1.1 200 OK\r\nContent-Length: 200000\r\n\r\n" + big
    req = req_from("GET http://h/ HTTP/1.1\r\nHost: h\r\n\r\n")
    res, _, reply, stats = run_forward(req, site)
    assert res.error is None, res.error
    assert len(reply) == res.bytes_down == stats.snapshot()["bytes_down"]
    assert reply.endswith(big)


def test_site_closes_without_answering_gives_502():
    req = req_from("GET http://h/ HTTP/1.1\r\nHost: h\r\n\r\n")
    res, _, _, _ = run_forward(req, site_close_early=True)
    assert isinstance(res, HttpError) and res.status == 502


def test_garbage_response_gives_502():
    req = req_from("GET http://h/ HTTP/1.1\r\nHost: h\r\n\r\n")
    res, _, _, _ = run_forward(req, b"NOT HTTP AT ALL\r\n\r\n")
    assert isinstance(res, HttpError) and res.status == 502


def test_client_vanishing_mid_body_gives_400():
    head = "POST http://h/p HTTP/1.1\r\nHost: h\r\nContent-Length: 100\r\n\r\n"
    req = req_from(head)
    res, _, _, _ = run_forward(req, b"", client_body=b"only-ten-b", client_hangs_up=True)
    assert isinstance(res, HttpError) and res.status == 400


def test_expect_continue_gets_100_first():
    body = b"hello"
    head = ("POST http://h/p HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n"
            "Expect: 100-continue\r\n\r\n")
    req = req_from(head)
    res, seen, reply, _ = run_forward(req, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
                                      client_body=body)
    assert reply.startswith(b"HTTP/1.1 100 Continue\r\n\r\n")
    assert b"expect" not in seen.lower()                    # never forwarded to the site
    assert seen.endswith(b"hello")
