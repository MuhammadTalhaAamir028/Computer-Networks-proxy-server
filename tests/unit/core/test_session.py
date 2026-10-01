"""tests/unit/core/test_session.py -- one client's whole life, using a socketpair as the client.

Rules under test (from session.py): auth before filter, filter before connect,
and `finally` always logs conn_close once and puts active_conns back to 0.
"""
import socket

from proxy.core.registry import TunnelRegistry
from proxy.core.session import Session, SessionContext
from proxy.stubs import AllowAllFilter, DictConfig, MemoryStats, NoAuth
from tests.conftest import DenyAuth, DenyFilter, HttpOrigin, RecLogger, recv_all

CFG = {"proxy": {"host": "127.0.0.1", "port": 8080, "connect_timeout": 2,
                 "read_timeout": 2, "idle_timeout": 2, "max_header_bytes": 4096}}


def run_session(request: bytes, filt=None, auth=None, close_write=True):
    """Feed `request` to a Session over a socketpair. Returns (reply_bytes, logger, stats)."""
    logger, stats = RecLogger(), MemoryStats()
    ctx = SessionContext(config=DictConfig(CFG), filt=filt or AllowAllFilter(),
                         auth=auth or NoAuth(), logger=logger, stats=stats,
                         registry=TunnelRegistry())
    proxy_side, test_side = socket.socketpair()
    test_side.settimeout(3)
    test_side.sendall(request)
    if close_write:
        test_side.shutdown(socket.SHUT_WR)
    Session(ctx, proxy_side, ("10.1.2.3", 5555), 7).run()
    reply = recv_all(test_side)
    test_side.close()
    return reply, logger, stats


def assert_closed_once(logger, stats, outcome):
    assert stats.snapshot()["active_conns"] == 0, "active_conns leaked"
    assert len(logger.of("conn_open")) == 1
    closes = logger.of("conn_close")
    assert len(closes) == 1
    assert closes[0]["outcome"] == outcome
    assert closes[0]["conn_id"] == 7


def test_good_request_is_forwarded_and_logged():
    origin = HttpOrigin()
    req = (f"GET http://127.0.0.1:{origin.port}/ HTTP/1.1\r\n"
           f"Host: 127.0.0.1:{origin.port}\r\n\r\n").encode()
    reply, logger, stats = run_session(req)
    assert b"200 OK" in reply and reply.endswith(b"origin ok")
    assert_closed_once(logger, stats, "ok")
    fwd = logger.of("req_forward")
    assert len(fwd) == 1 and fwd[0]["status"] == 200
    assert stats.snapshot()["requests_total"] == 1
    origin.close()


def test_blocked_host_gets_403_and_never_touches_the_origin():
    origin = HttpOrigin()
    req = (f"GET http://localhost:{origin.port}/ HTTP/1.1\r\nHost: localhost\r\n\r\n").encode()
    reply, logger, stats = run_session(req, filt=DenyFilter(deny_host="localhost"))
    assert reply.startswith(b"HTTP/1.1 403")
    assert origin.accepted == 0, "proxy connected upstream for a blocked request"
    assert_closed_once(logger, stats, "blocked")
    assert len(logger.of("req_blocked")) == 1
    assert stats.snapshot()["requests_blocked"] == 1
    origin.close()


def test_failed_auth_gets_407_and_never_touches_the_origin():
    origin = HttpOrigin()
    req = (f"GET http://127.0.0.1:{origin.port}/ HTTP/1.1\r\nHost: x\r\n\r\n").encode()
    reply, logger, stats = run_session(req, auth=DenyAuth())
    assert reply.startswith(b"HTTP/1.1 407")
    assert origin.accepted == 0
    assert_closed_once(logger, stats, "blocked")
    fail = logger.of("auth_fail")
    assert len(fail) == 1 and fail[0]["reason"] == "missing"
    origin.close()


def test_locked_client_gets_429():
    req = b"GET http://127.0.0.1:9/ HTTP/1.1\r\nHost: x\r\n\r\n"
    reply, logger, stats = run_session(req, auth=DenyAuth(locked=True))
    assert reply.startswith(b"HTTP/1.1 429")
    assert_closed_once(logger, stats, "blocked")


def test_auth_runs_before_filter():
    """Unauthenticated clients must not learn what the filter blocks."""
    req = b"GET http://localhost:9/ HTTP/1.1\r\nHost: localhost\r\n\r\n"
    reply, logger, _ = run_session(req, filt=DenyFilter(deny_host="localhost"),
                                   auth=DenyAuth())
    assert reply.startswith(b"HTTP/1.1 407")
    assert logger.of("req_blocked") == []


def test_malformed_request_gets_400_and_cleans_up():
    reply, logger, stats = run_session(b"THIS IS NOT HTTP\r\n\r\n")
    assert reply.startswith(b"HTTP/1.1 400")
    assert_closed_once(logger, stats, "error")
    assert stats.snapshot()["errors"] == 1


def test_client_that_sends_nothing_does_not_leak():
    reply, logger, stats = run_session(b"")
    assert_closed_once(logger, stats, logger.of("conn_close")[0]["outcome"])


def test_unresolvable_host_gets_502():
    req = b"GET http://no-such-host.invalid/ HTTP/1.1\r\nHost: x\r\n\r\n"
    reply, logger, stats = run_session(req)
    assert reply.startswith(b"HTTP/1.1 502")
    assert_closed_once(logger, stats, "error")


def test_unexpected_exception_gives_500_and_still_decrements():
    class Boom(AllowAllFilter):
        def check(self, *a):
            raise RuntimeError("filter exploded")

    req = b"GET http://127.0.0.1:9/ HTTP/1.1\r\nHost: x\r\n\r\n"
    reply, logger, stats = run_session(req, filt=Boom())
    assert reply.startswith(b"HTTP/1.1 500")
    assert_closed_once(logger, stats, "error")
    err = logger.of("error")[0]
    assert err["error"] == "RuntimeError" and err["where"] == "session"


def test_ip_denied_after_dns_gives_403_with_no_connection():
    """check() allows the name; check_ip() denies the resolved address (SSRF guard)."""
    origin = HttpOrigin()
    req = (f"GET http://127.0.0.1:{origin.port}/ HTTP/1.1\r\nHost: x\r\n\r\n").encode()
    flt = DenyFilter(deny_ip="127.0.0.1")
    reply, logger, stats = run_session(req, filt=flt)
    assert reply.startswith(b"HTTP/1.1 403")
    assert flt.ip_calls, "check_ip was never asked"
    assert origin.accepted == 0
    assert_closed_once(logger, stats, "blocked")
    assert logger.of("req_blocked")[0]["path"] is None      # IP-stage block has no path
    origin.close()


def test_no_secrets_reach_the_events():
    """Core must never pass header values as event fields."""
    req = (b"GET http://127.0.0.1:9/ HTTP/1.1\r\nHost: x\r\n"
           b"Proxy-Authorization: Basic c2VjcmV0OnNlY3JldA==\r\n\r\n")
    _, logger, _ = run_session(req, auth=DenyAuth())
    for ev in logger.events:
        assert "authorization" not in ev
        assert "c2VjcmV0" not in str(ev)
