"""Unit tests for tools/smoke.py, run against a tiny fake proxy (no real proxy needed)."""
from __future__ import annotations

import base64
import socket
import threading
from urllib.parse import urlsplit

import pytest

from tools import smoke
from tools.origin import OriginServers

DENIED = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
CHALLENGE = (b"HTTP/1.1 407 Proxy Authentication Required\r\n"
             b"Proxy-Authenticate: Basic realm=\"proxy\"\r\n"
             b"Content-Length: 0\r\nConnection: close\r\n\r\n")


def read_head(sock):
    """Read a request head (up to the blank line) from a client socket."""
    data = b""
    while not data.endswith(b"\r\n\r\n"):
        chunk = sock.recv(1)
        if not chunk:
            break
        data += chunk
    return data


def pipe(src, dst):
    """Copy bytes from src to dst until src closes."""
    try:
        while True:
            data = src.recv(4096)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    try:
        dst.shutdown(socket.SHUT_WR)
    except OSError:
        pass


class FakeProxy:
    """Just enough of a forward proxy to exercise smoke.py. TEST ONLY."""

    def __init__(self, blocked_host="blocked.example.com", require_auth=False,
                 rewrite=True):
        self.blocked_host = blocked_host
        self.require_auth = require_auth
        self.rewrite = rewrite  # False simulates a proxy that forgets to rewrite the line
        self._sock = socket.socket()
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(16)
        self.port = self._sock.getsockname()[1]
        threading.Thread(target=self._accept_loop, daemon=True).start()

    def stop(self):
        self._sock.close()

    def _accept_loop(self):
        while True:
            try:
                client, _ = self._sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(client,), daemon=True).start()

    def _serve(self, client):
        try:
            client.settimeout(10)
            lines = read_head(client).decode("latin-1").split("\r\n")
            method, target, _ = lines[0].split(" ", 2)
            headers = {k.strip().lower(): v for k, v in
                       (line.split(":", 1) for line in lines[1:] if ":" in line)}
            if self.require_auth and "proxy-authorization" not in headers:
                client.sendall(CHALLENGE)
            elif method == "CONNECT":
                self._tunnel(client, target)
            else:
                self._forward(client, target)
        except (OSError, ValueError):
            pass
        finally:
            client.close()

    def _forward(self, client, target):
        parts = urlsplit(target)
        if parts.hostname == self.blocked_host:
            client.sendall(DENIED)
            return
        path = parts.path + (f"?{parts.query}" if parts.query else "")
        request_target = path if self.rewrite else target
        with socket.create_connection((parts.hostname, parts.port or 80)) as upstream:
            upstream.sendall(f"GET {request_target} HTTP/1.1\r\nHost: {parts.netloc}\r\n"
                             "Connection: close\r\n\r\n".encode("ascii"))
            while True:
                data = upstream.recv(4096)
                if not data:
                    break
                client.sendall(data)

    def _tunnel(self, client, target):
        host, port = target.rsplit(":", 1)
        with socket.create_connection((host, int(port))) as upstream:
            client.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            forward = threading.Thread(target=pipe, args=(client, upstream), daemon=True)
            forward.start()
            pipe(upstream, client)
            forward.join(timeout=5)


@pytest.fixture(scope="module")
def origin():
    """Real test origin servers on free ports."""
    servers = OriginServers(http_port=0, tls_port=0)
    servers.start()
    yield servers
    servers.stop()


@pytest.fixture
def fake_proxy_factory():
    """Create fake proxies and stop them all afterwards."""
    made = []

    def factory(**kwargs):
        proxy = FakeProxy(**kwargs)
        made.append(proxy)
        return proxy

    yield factory
    for proxy in made:
        proxy.stop()


def run_smoke(origin, proxy_port, *extra):
    """Call smoke.main with the right addresses; return (exit code)."""
    return smoke.main(["--proxy", f"127.0.0.1:{proxy_port}",
                       "--origin", f"127.0.0.1:{origin.http_port}",
                       "--tls-origin", f"127.0.0.1:{origin.tls_port}", *extra])


def test_all_checks_pass_against_a_working_proxy(origin, fake_proxy_factory, capsys):
    proxy = fake_proxy_factory()
    assert run_smoke(origin, proxy.port) == 0
    out = capsys.readouterr().out
    assert "6 passed, 0 failed, 1 skipped" in out  # the 407 check is skipped without --auth


def test_auth_check_passes_and_credentials_are_not_printed(origin, fake_proxy_factory, capsys):
    proxy = fake_proxy_factory(require_auth=True)
    assert run_smoke(origin, proxy.port, "--auth", "alice:S3cr3tPass!") == 0
    out = capsys.readouterr().out
    assert "7 passed, 0 failed, 0 skipped" in out
    secret_b64 = base64.b64encode(b"alice:S3cr3tPass!").decode()
    assert "S3cr3tPass" not in out and secret_b64 not in out  # no secrets in output


def test_fails_when_proxy_lets_anonymous_users_through(origin, fake_proxy_factory, capsys):
    proxy = fake_proxy_factory(require_auth=False)  # no login, but we claim login is on
    assert run_smoke(origin, proxy.port, "--auth", "alice:pw") == 1
    assert "FAIL" in capsys.readouterr().out


def test_fails_when_request_line_is_not_rewritten(origin, fake_proxy_factory, capsys):
    proxy = fake_proxy_factory(rewrite=False)
    assert run_smoke(origin, proxy.port) == 1
    out = capsys.readouterr().out
    row = next(line for line in out.splitlines() if line.startswith("request line rewritten"))
    assert "FAIL" in row


def test_fails_when_blocked_domain_is_allowed(origin, fake_proxy_factory, capsys):
    proxy = fake_proxy_factory(blocked_host="some-other-host.test")
    assert run_smoke(origin, proxy.port) == 1
    out = capsys.readouterr().out
    row = next(line for line in out.splitlines() if line.startswith("blocked domain"))
    assert "FAIL" in row


def test_dead_proxy_fails_every_check_without_crashing(origin, capsys):
    with socket.socket() as sock:  # grab a free port, then close it so nothing listens
        sock.bind(("127.0.0.1", 0))
        dead_port = sock.getsockname()[1]
    assert run_smoke(origin, dead_port) == 1
    assert "0 passed, 6 failed, 1 skipped" in capsys.readouterr().out


@pytest.mark.parametrize("text, expected", [("127.0.0.1:8080", ("127.0.0.1", 8080)),
                                            ("localhost:1", ("localhost", 1))])
def test_parse_hostport_accepts_valid_input(text, expected):
    assert smoke.parse_hostport(text) == expected


@pytest.mark.parametrize("text", ["nohost", ":8080", "host:", "host:abc", "host:0", "host:70000"])
def test_parse_hostport_rejects_bad_input(text):
    with pytest.raises(ValueError):
        smoke.parse_hostport(text)