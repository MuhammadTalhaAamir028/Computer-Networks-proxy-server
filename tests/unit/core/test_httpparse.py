"""tests/unit/core/test_httpparse.py -- tests for the request parser."""
import pytest
from proxy.core.httpparse import parse_head, BadRequest

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


# ============================================================
# STAGE 3: VALIDATION (garbage in -> BadRequest out, never a crash)
# ============================================================

def test_connect_without_port_is_rejected():
    """CONNECT example.com (no :port) -> BadRequest with status 400."""
    head = (b"CONNECT example.com HTTP/1.1\r\n"
            b"Host: example.com\r\n"
            b"\r\n")
    with pytest.raises(BadRequest) as err:
        parse_head(head)
    assert err.value.status == 400

def test_request_line_with_two_parts_is_rejected():
    """'GET /' has no HTTP version -> BadRequest 400, not a crash."""
    head = (b"GET /\r\n"
            b"Host: example.com\r\n"
            b"\r\n")
    with pytest.raises(BadRequest) as err:
        parse_head(head)
    assert err.value.status == 400