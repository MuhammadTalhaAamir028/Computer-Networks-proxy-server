"""proxy/stubs.py -- fake modules so any member can run and test alone."""
import threading
from .interfaces import AuthResult, Decision, STAT_KEYS

class AllowAllFilter:
    def check(self, host, port, path, method): return Decision(True)
    def check_ip(self, ip, port): return Decision(True)
    def describe(self): return {"mode": "stub"}
    def forbidden_response(self, decision):
        return b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"

class NoAuth:
    def check(self, headers, client_ip): return AuthResult(ok=True)
    def challenge_response(self):
        return (b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                b"Proxy-Authenticate: Basic realm=\"proxy\"\r\n"
                b"Content-Length: 0\r\nConnection: close\r\n\r\n")
    def locked_response(self, retry_after):
        return b"HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    def recent_failures(self, limit=50): return []

class NullLogger:
    def event(self, kind, **fields): pass
    def tail(self, n=100): return []

class MemoryStats:
    def __init__(self):
        self._lock = threading.Lock()
        self._c = {k: 0 for k in STAT_KEYS}
    def inc(self, name, n=1):
        with self._lock: self._c[name] = self._c.get(name, 0) + n
    def snapshot(self):
        with self._lock: return dict(self._c)

class DictConfig:
    def __init__(self, data=None):
        self._d, self.last_error = data or {}, None
    def get(self, key, default=None):
        cur = self._d
        for part in key.split("."):
            if not isinstance(cur, dict) or part not in cur: return default
            cur = cur[part]
        return cur
    def reload(self): return True
    def as_dict(self, redact=True): return dict(self._d)