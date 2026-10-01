"""proxy/core/server.py -- the listener: accepts clients and gives each one a thread.

Rules:
    - at most proxy.max_threads sessions at once (BoundedSemaphore); overflow gets a 503
    - the accept loop never blocks on a client
    - accept() errors are logged and survived; only shutdown() ends the loop
"""
import itertools
import os
import socket
import threading
import time

from .errors import build_error
from .registry import TunnelRegistry
from .session import Session, SessionContext, _close


class ProxyServer:
    """ProxyServer(config, filter_engine, auth, logger, stats)."""

    def __init__(self, config, filter_engine, auth, logger, stats):
        self.config, self.logger, self.stats = config, logger, stats
        self.registry = TunnelRegistry()
        self._stop = threading.Event()
        self._ids = itertools.count(1)
        self._id_lock = threading.Lock()
        self._sessions = {}                      # conn_id -> Session (for shutdown)
        self._sessions_lock = threading.Lock()
        self._last_pool_log = 0.0
        max_threads = int(config.get("proxy.max_threads", 100) or 100)
        self._slots = threading.BoundedSemaphore(max_threads)
        self._reject_slots = threading.BoundedSemaphore(32)   # cap on in-flight 503 replies
        self._listener = self._bind()
        self._port = self._listener.getsockname()[1]    # saved: still valid after close
        self.ctx = SessionContext(config=config, filt=filter_engine, auth=auth,
                                  logger=logger, stats=stats, registry=self.registry,
                                  own_ports=self._own_ports)

    # ------------------------------------------------------------
    # setup
    # ------------------------------------------------------------
    def _bind(self):
        """Create, configure and bind the listening socket."""
        host = str(self.config.get("proxy.host", "127.0.0.1"))
        port = int(self.config.get("proxy.port", 8080))
        backlog = int(self.config.get("proxy.backlog", 128))
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        try:
            if os.name == "nt":                  # SO_REUSEADDR would allow port hijacking
                if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            else:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((host, port))
            sock.listen(backlog)
            sock.settimeout(0.5)                 # so the loop can notice shutdown()
        except OSError:
            sock.close()
            raise
        return sock

    @property
    def port(self) -> int:
        """The real bound port (so proxy.port = 0 works in tests)."""
        return self._port

    def _own_ports(self):
        """Ports that mean 'the proxy itself' (self-loop guard)."""
        ports = {self.port}
        admin = self.config.get("admin.port", 0)
        if isinstance(admin, int) and admin > 0:
            ports.add(admin)
        return ports

    def active_tunnels(self) -> list:
        """Copies of the open tunnels, safe to serialise."""
        return self.registry.snapshot()

    def _next_id(self) -> int:
        with self._id_lock:
            return next(self._ids)

    # ------------------------------------------------------------
    # accept loop
    # ------------------------------------------------------------
    def serve_forever(self):
        """Accept clients until shutdown()."""
        while not self._stop.is_set():
            try:
                client, addr = self._listener.accept()
            except socket.timeout:
                continue
            except OSError as exc:
                if self._stop.is_set():
                    break
                self._log_error("accept", exc)
                time.sleep(0.05)
                continue
            if not self._slots.acquire(blocking=False):
                self._reject_overflow(client)
                continue
            self._start_session(client, addr)

    def _start_session(self, client, addr):
        session = Session(self.ctx, client, addr, self._next_id())
        with self._sessions_lock:
            self._sessions[session.conn_id] = session
        try:
            threading.Thread(target=self._run, args=(session,), daemon=True).start()
        except RuntimeError as exc:              # the OS refused a new thread
            self._finish(session)
            _close(client)
            self._log_error("accept", exc)

    def _run(self, session):
        try:
            session.run()
        finally:
            self._finish(session)

    def _finish(self, session):
        with self._sessions_lock:
            self._sessions.pop(session.conn_id, None)
        self._slots.release()

    def _reject_overflow(self, client):
        """Thread cap reached: answer 503 without ever blocking the accept loop.

        The 503 is sent from a tiny helper thread that uses a *lingering close*:
        send, half-close, then read what the client still sends before closing.
        Closing at once with unread request bytes makes Windows send a TCP RST,
        which throws the 503 away before the client can read it.
        """
        now = time.monotonic()
        if now - self._last_pool_log >= 1.0:     # at most one log line per second
            self._last_pool_log = now
            self._log_error("accept", RuntimeError("PoolFull"), "thread pool is full",
                            name="PoolFull")
        if not self._reject_slots.acquire(blocking=False):
            _close(client)                       # flood: too many rejects in flight, drop hard
            return
        try:
            threading.Thread(target=self._send_503, args=(client,), daemon=True).start()
        except RuntimeError:
            self._reject_slots.release()
            _close(client)

    def _send_503(self, client):
        try:
            client.settimeout(0.5)
            client.sendall(build_error(503, "server busy, try again", retry_after=1))
            client.shutdown(socket.SHUT_WR)      # "I'm done sending" -> client reads the 503
            client.settimeout(0.1)
            end = time.monotonic() + 0.5
            while time.monotonic() < end:        # swallow the request bytes still arriving
                if not client.recv(4096):
                    break
        except OSError:
            pass
        finally:
            _close(client)
            self._reject_slots.release()

    def _log_error(self, where, exc, message="", name=None):
        self.logger.event("error", where=where, error=name or type(exc).__name__,
                          message=message or str(exc))
        self.stats.inc("errors")

    # ------------------------------------------------------------
    # shutdown
    # ------------------------------------------------------------
    def shutdown(self, timeout: float = 5.0):
        """Stop accepting, wait for sessions, then force-close the rest. Idempotent."""
        self._stop.set()
        try:
            self._listener.close()
        except OSError:
            pass
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._sessions_lock:
                if not self._sessions:
                    return
            time.sleep(0.02)
        with self._sessions_lock:
            leftovers = list(self._sessions.values())
        for session in leftovers:
            _close(session.client)
            _close(session.upstream)