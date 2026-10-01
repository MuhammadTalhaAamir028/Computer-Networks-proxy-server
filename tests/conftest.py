"""tests/conftest.py -- shared helpers: fake origins, a recording logger, a proxy fixture.

Everything here uses real localhost sockets and the stub teammates from proxy/stubs.py,
so core tests run alone (no obs/control branches needed).
"""
import socket
import threading
import time

import pytest

from proxy.core import ProxyServer
from proxy.stubs import AllowAllFilter, DictConfig, MemoryStats, NoAuth


def wait_for(cond, timeout=3.0, step=0.01):
    """Poll until cond() is true. Returns the last value of cond()."""
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if cond():
            return True
        time.sleep(step)
    return bool(cond())


class RecLogger:
    """Logger that remembers every event, so tests can assert on them."""

    def __init__(self):
        self.events = []
        self._lock = threading.Lock()

    def event(self, kind, **fields):
        with self._lock:
            self.events.append({"kind": kind, **fields})

    def tail(self, n=100):
        with self._lock:
            return list(self.events[-n:])

    def of(self, kind):
        with self._lock:
            return [e for e in self.events if e["kind"] == kind]


class DenyFilter(AllowAllFilter):
    """Denies one host by name (check) and/or one IP (check_ip). Records check_ip calls."""

    def __init__(self, deny_host=None, deny_ip=None):
        self.deny_host, self.deny_ip, self.ip_calls = deny_host, deny_ip, []

    def check(self, host, port, path, method):
        from proxy.interfaces import Decision
        if host == self.deny_host:
            return Decision(False, "blocked by test", rule="deny:domain:" + host)
        return Decision(True)

    def check_ip(self, ip, port):
        from proxy.interfaces import Decision
        self.ip_calls.append((ip, port))
        if ip == self.deny_ip:
            return Decision(False, "ip blocked", rule="deny:ip:" + ip)
        return Decision(True)


class DenyAuth(NoAuth):
    """Always rejects. Lets tests check that auth failure never reaches the upstream."""

    def __init__(self, locked=False):
        self.locked = locked

    def check(self, headers, client_ip):
        from proxy.interfaces import AuthResult
        if self.locked:
            return AuthResult(ok=False, locked=True, retry_after=30, reason="locked")
        return AuthResult(ok=False, reason="missing")


class HttpOrigin:
    """Tiny HTTP origin. Replies 'origin ok'. Counts accepted connections."""

    def __init__(self, delay=0.0):
        self.delay, self.accepted = delay, 0
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(128)
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            self.accepted += 1
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn):
        try:
            conn.settimeout(5)
            buf = b""
            while b"\r\n\r\n" not in buf:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                buf += chunk
            time.sleep(self.delay)
            body = b"origin ok"
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n"
                         b"Connection: close\r\n\r\n%s" % (len(body), body))
        except OSError:
            pass
        finally:
            conn.close()

    def close(self):
        self.sock.close()


class EchoOrigin:
    """Plain TCP echo server (stands in for the TLS site behind a CONNECT tunnel)."""

    def __init__(self):
        self.accepted = 0
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(128)
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            self.accepted += 1
            threading.Thread(target=self._echo, args=(conn,), daemon=True).start()

    @staticmethod
    def _echo(conn):
        try:
            while True:
                data = conn.recv(4096)
                if not data:
                    break
                conn.sendall(data)
        except OSError:
            pass
        finally:
            conn.close()

    def close(self):
        self.sock.close()


class RunningProxy:
    """A ProxyServer running on a random port in a background thread."""

    def __init__(self, config, filt, auth, logger, stats):
        self.logger, self.stats = logger, stats
        self.server = ProxyServer(config, filt, auth, logger, stats)
        self.port = self.server.port
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def active(self):
        return self.stats.snapshot()["active_conns"]

    def connect(self):
        s = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        return s


def recv_all(sock, limit=1 << 20):
    """Read until the peer closes (or timeout). Returns bytes."""
    out = b""
    try:
        while len(out) < limit:
            chunk = sock.recv(65536)
            if not chunk:
                break
            out += chunk
    except OSError:
        pass
    return out


@pytest.fixture
def http_origin():
    o = HttpOrigin()
    yield o
    o.close()


@pytest.fixture
def echo_origin():
    o = EchoOrigin()
    yield o
    o.close()


@pytest.fixture
def make_proxy():
    """Factory: make_proxy(filt=..., auth=..., **config_overrides) -> RunningProxy."""
    started = []

    def factory(filt=None, auth=None, **proxy_cfg):
        cfg = {"host": "127.0.0.1", "port": 0, "max_threads": 100, "backlog": 128,
               "connect_timeout": 3, "read_timeout": 5, "idle_timeout": 5,
               "max_header_bytes": 16384}
        cfg.update(proxy_cfg)
        config = DictConfig({"proxy": cfg, "admin": {"port": 0}})
        rp = RunningProxy(config, filt or AllowAllFilter(), auth or NoAuth(),
                          RecLogger(), MemoryStats())
        started.append(rp)
        return rp

    yield factory
    for rp in started:
        rp.server.shutdown(timeout=2)
