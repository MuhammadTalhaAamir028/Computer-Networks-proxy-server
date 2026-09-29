"""tests/unit/core/test_httpparse.py -- tests for the request parser."""
from proxy.core.httpparse import parse_head

# ============================================================
# STAGE 2 + 4: a normal proxy request is understood
# ============================================================

def test_absolute_uri_with_port():
    """GET http://example.com:8000/a?x=1 -> host, port, path split out."""
    head = (b"GET http://example.com:8000/a?x=1 HTTP/1.1\r\n"
            b"Host: example.com:8000\r\n"
            b"\r\n")
    req = parse_head(head)
    assert req.method == "GET"
    assert req.host == "example.com"
    assert req.port == 8000
    assert req.path == "/a?x=1"
    assert req.version == "HTTP/1.1"
    assert req.headers["host"] == "example.com:8000"

    # ============================================================
    # STAGE 4: CONNECT requests (HTTPS tunnels)
    # ============================================================

def test_connect_host_and_port():
    """CONNECT example.com:443 -> host, port; path is None (no path in CONNECT)."""
    head = (b"CONNECT example.com:443 HTTP/1.1\r\n"
            b"Host: example.com:443\r\n"
            b"\r\n")
    req = parse_head(head)
    assert req.method == "CONNECT"
    assert req.host == "example.com"
    assert req.port == 443
    assert req.path is None