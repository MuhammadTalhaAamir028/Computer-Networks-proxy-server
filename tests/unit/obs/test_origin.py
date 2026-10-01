"""Unit tests for tools/origin.py (HTTP routes and TLS echo)."""
from __future__ import annotations

import http.client
import json
import socket
import ssl
import time

import pytest

from tools.origin import OriginServers


@pytest.fixture(scope="module")
def origin():
    """Start the origin on free ports for the whole module."""
    servers = OriginServers(http_port=0, tls_port=0)
    servers.start()
    yield servers
    servers.stop()


def get(origin, path, method="GET", body=None, headers=None):
    """Make one request and return (status, headers, body bytes)."""
    conn = http.client.HTTPConnection("127.0.0.1", origin.http_port, timeout=10)
    conn.request(method, path, body=body, headers=headers or {})
    resp = conn.getresponse()
    data = resp.read()
    conn.close()
    return resp.status, resp, data


def test_root_ok(origin):
    status, _, body = get(origin, "/")
    assert status == 200 and body == b"origin ok"


def test_status_routes(origin):
    assert get(origin, "/404")[0] == 404
    assert get(origin, "/status/418")[0] == 418
    assert get(origin, "/status/204")[2] == b""
    assert get(origin, "/status/abc")[0] == 400
    assert get(origin, "/nothing-here")[0] == 404


def test_slow_waits(origin):
    start = time.monotonic()
    status, _, _ = get(origin, "/slow?ms=200")
    assert status == 200 and time.monotonic() - start >= 0.2
    assert get(origin, "/slow?ms=abc")[0] == 400


def test_big_is_deterministic(origin):
    status, resp, body = get(origin, "/big?mb=1")
    assert status == 200
    assert resp.getheader("Content-Length") == str(1024 * 1024)
    assert len(body) == 1024 * 1024
    assert body[:256] == bytes(range(256))


def test_chunked_five_chunks(origin):
    start = time.monotonic()
    status, resp, body = get(origin, "/chunked")
    assert status == 200
    assert resp.getheader("Transfer-Encoding") == "chunked"
    assert body == b"".join(f"chunk {i}\n".encode() for i in range(1, 6))
    assert time.monotonic() - start >= 0.4


def test_echo_get_and_post(origin):
    _, _, body = get(origin, "/echo?x=1", headers={"X-Test": "abc"})
    data = json.loads(body)
    assert data["method"] == "GET" and data["path"] == "/echo?x=1"
    assert data["headers"]["x-test"] == "abc"
    _, _, body = get(origin, "/echo", method="POST", body=b"hello world")
    assert json.loads(body)["body_length"] == 11


def test_drop_closes_early_and_server_survives(origin):
    conn = http.client.HTTPConnection("127.0.0.1", origin.http_port, timeout=10)
    conn.request("GET", "/drop?after=1000")
    resp = conn.getresponse()
    with pytest.raises(http.client.IncompleteRead) as info:
        resp.read()
    assert len(info.value.partial) == 1000
    conn.close()
    assert get(origin, "/")[0] == 200


def tls_client(origin):
    """Open a TLS connection to the echo server with verification off."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    raw = socket.create_connection(("127.0.0.1", origin.tls_port), timeout=10)
    return ctx.wrap_socket(raw, server_hostname="localhost")


def test_tls_echo_round_trip(origin):
    with tls_client(origin) as tls:
        tls.sendall(b"hello proxy")
        assert tls.recv(4096) == b"hello proxy"


def test_stats_count_requests_and_tls(origin):
    before = json.loads(get(origin, "/__stats")[2])
    get(origin, "/")
    with tls_client(origin) as tls:
        tls.sendall(b"x")
        tls.recv(10)
    after = json.loads(get(origin, "/__stats")[2])
    assert after["http_requests"] == before["http_requests"] + 1
    assert after["tls_connections"] == before["tls_connections"] + 1
    assert after["http_connections"] >= before["http_connections"] + 1