"""tests/unit/core/test_upstream.py -- resolve, SSRF guard, self-loop guard, connect."""
import socket

import pytest

from proxy.core.upstream import UpstreamError, connect_upstream
from tests.conftest import DenyFilter
from proxy.stubs import AllowAllFilter


def _listener():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen(5)
    return s, s.getsockname()[1]


def test_connects_to_resolved_ip_and_returns_it():
    srv, port = _listener()
    sock, ip = connect_upstream("127.0.0.1", port, AllowAllFilter(), 2, 2)
    assert ip == "127.0.0.1"
    sock.close(); srv.close()


def test_filter_sees_the_resolved_ip_not_the_name():
    srv, port = _listener()
    flt = DenyFilter()
    sock, _ = connect_upstream("localhost", port, flt, 2, 2)
    assert flt.ip_calls, "check_ip was never called"
    assert all(ip in ("127.0.0.1", "::1") for ip, _ in flt.ip_calls)
    sock.close(); srv.close()


def test_denied_ip_gives_403_with_decision_and_no_connection():
    srv, port = _listener()
    srv.settimeout(0.3)
    with pytest.raises(UpstreamError) as exc:
        connect_upstream("127.0.0.1", port, DenyFilter(deny_ip="127.0.0.1"), 2, 2)
    assert exc.value.status == 403
    assert exc.value.decision is not None and not exc.value.decision.allowed
    with pytest.raises(socket.timeout):                  # nobody connected to the listener
        srv.accept()
    srv.close()


def test_self_loop_is_refused():
    srv, port = _listener()
    with pytest.raises(UpstreamError) as exc:
        connect_upstream("127.0.0.1", port, AllowAllFilter(), 2, 2,
                         own_ports={port}, proxy_host="127.0.0.1")
    assert exc.value.status == 403
    assert exc.value.decision.rule == "self-loop"
    srv.close()


def test_unresolvable_host_gives_502():
    with pytest.raises(UpstreamError) as exc:
        connect_upstream("no-such-host.invalid", 80, AllowAllFilter(), 2, 2)
    assert exc.value.status == 502


def test_closed_port_gives_a_clean_error():
    srv, port = _listener()
    srv.close()                                          # nothing listens now
    with pytest.raises(UpstreamError) as exc:
        connect_upstream("127.0.0.1", port, AllowAllFilter(), 2, 2)
    assert exc.value.status in (502, 504)
