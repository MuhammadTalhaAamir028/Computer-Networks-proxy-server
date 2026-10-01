"""proxy/core/session.py -- ONE client connection, start to finish (runs in its own thread).

Call order (mandatory):
    read head -> parse -> AUTH -> FILTER -> resolve + connect -> CONNECT tunnel | HTTP forward
Blocked or unauthenticated traffic must never cause an upstream connection.
A `finally` always closes both sockets and logs conn_close exactly once.
"""
import socket
import time
from dataclasses import dataclass, field
from typing import Callable

from .errors import HttpError, build_error
from .forward import forward_http
from .httpparse import parse_head, read_head
from .tunnel import run_tunnel
from .upstream import UpstreamError, connect_upstream


@dataclass
class SessionContext:
    """Everything a session needs. Built once by the server, shared read-only."""
    config: object
    filt: object
    auth: object
    logger: object
    stats: object
    registry: object
    own_ports: Callable = field(default=lambda: set())   # ports that mean "the proxy itself"


def _cfg(config, key, default):
    value = config.get(key, default)
    return default if value is None else value


def _close(sock):
    if sock is None:
        return
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    try:
        sock.close()
    except OSError:
        pass


class Session:
    """Handles one accepted client socket."""

    def __init__(self, ctx: SessionContext, client, addr, conn_id: int):
        self.ctx, self.client, self.conn_id = ctx, client, conn_id
        self.client_ip, self.client_port = addr[0], addr[1]
        self.upstream = None
        self.replied = False          # True once any response byte went to the client
        self.bytes_up = self.bytes_down = 0
        self.outcome = "ok"

    # ------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------
    def _send(self, data: bytes):
        """Send a full reply to the client. Never raises."""
        try:
            self.client.sendall(data)
            self.replied = True
        except OSError:
            pass

    def _error_event(self, where: str, exc: BaseException, message: str = ""):
        self.ctx.logger.event("error", conn_id=self.conn_id, where=where,
                              error=type(exc).__name__, message=message or str(exc))
        self.ctx.stats.inc("errors")

    def _reply_error(self, exc: HttpError, where: str):
        """Send the error page for `exc` and record it."""
        self._send(build_error(exc.status, exc.message))
        self._error_event(where, exc, exc.message)
        self.outcome = "timeout" if exc.status in (408, 504) else "error"

    def _block(self, decision, method, host, port, path):
        """Send the filter's 403 and record the block."""
        self._send(self.ctx.filt.forbidden_response(decision))
        self.ctx.logger.event("req_blocked", conn_id=self.conn_id, method=method, host=host,
                              port=port, path=path, rule=decision.rule, reason=decision.reason)
        self.ctx.stats.inc("requests_blocked")
        self.outcome = "blocked"

    # ------------------------------------------------------------
    # the whole life of one client
    # ------------------------------------------------------------
    def run(self):
        ctx, started = self.ctx, time.monotonic()
        ctx.stats.inc("active_conns")
        ctx.logger.event("conn_open", conn_id=self.conn_id,
                         client_ip=self.client_ip, client_port=self.client_port)
        try:
            self._handle()
        except Exception as exc:                         # never let it escape the thread
            self._error_event("session", exc)
            if not self.replied:
                self._send(build_error(500, "internal error"))
            self.outcome = "error"
        finally:
            _close(self.upstream)
            _close(self.client)
            ctx.stats.inc("active_conns", -1)
            ctx.logger.event("conn_close", conn_id=self.conn_id,
                             duration_ms=int((time.monotonic() - started) * 1000),
                             bytes_up=self.bytes_up, bytes_down=self.bytes_down,
                             outcome=self.outcome)

    def _handle(self):
        ctx, cfg = self.ctx, self.ctx.config
        read_timeout = float(_cfg(cfg, "proxy.read_timeout", 30))
        max_head = int(_cfg(cfg, "proxy.max_header_bytes", 16384))
        self.client.settimeout(read_timeout)
        try:
            self.client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass

        # --- STEP 1 + 2: read and parse the request ---
        try:
            head, leftover = read_head(self.client, max_head, read_timeout)
            req = parse_head(head)
        except HttpError as exc:
            self._reply_error(exc, "parse")
            return
        except OSError:                                  # client reset while sending
            self.outcome = "client_closed"
            return
        req.leftover = leftover
        ctx.stats.inc("requests_total")

        # --- STEP 3: authentication ---
        result = ctx.auth.check(req.headers, self.client_ip)
        if not result.ok:
            self._send(ctx.auth.locked_response(result.retry_after) if result.locked
                       else ctx.auth.challenge_response())
            ctx.logger.event("auth_fail", conn_id=self.conn_id, client_ip=self.client_ip,
                             user=result.user, reason=result.reason)
            self.outcome = "blocked"
            return

        # --- STEP 4: filter (no upstream connection exists yet) ---
        decision = ctx.filt.check(req.host, req.port, req.path, req.method)
        if not decision.allowed:
            self._block(decision, req.method, req.host, req.port, req.path)
            return

        # --- STEP 5: resolve + connect ---
        try:
            self.upstream, ip = connect_upstream(
                req.host, req.port, ctx.filt,
                float(_cfg(cfg, "proxy.connect_timeout", 10)), read_timeout,
                own_ports=ctx.own_ports(), proxy_host=str(_cfg(cfg, "proxy.host", "")))
        except UpstreamError as exc:
            if exc.decision is not None:
                self._block(exc.decision, req.method, req.host, req.port, None)
            else:
                self._reply_error(exc, "connect")
            return

        # --- STEP 6: tunnel or forward ---
        if req.method == "CONNECT":
            self._tunnel(req, ip)
        else:
            self._forward(req, max_head)

    def _tunnel(self, req, ip):
        cfg = self.ctx.config
        res = run_tunnel(self.client, self.upstream, conn_id=self.conn_id,
                         client_ip=self.client_ip, host=req.host, port=req.port, ip=ip,
                         leftover=req.leftover,
                         idle_timeout=float(_cfg(cfg, "proxy.idle_timeout", 60)),
                         stats=self.ctx.stats, logger=self.ctx.logger,
                         registry=self.ctx.registry)
        self.replied = True
        self.bytes_up, self.bytes_down = res.bytes_up, res.bytes_down
        self.outcome = {"client_closed": "client_closed", "upstream_closed": "ok",
                        "idle_timeout": "timeout", "error": "error"}[res.reason]

    def _forward(self, req, max_head):
        started = time.monotonic()
        try:
            res = forward_http(self.client, self.upstream, req, self.ctx.stats, max_head)
        except HttpError as exc:
            self._reply_error(exc, "forward")
            return
        self.replied = res.started
        self.bytes_up, self.bytes_down = res.bytes_up, res.bytes_down
        self.ctx.logger.event("req_forward", conn_id=self.conn_id, method=req.method,
                              host=req.host, port=req.port, path=req.path, status=res.status,
                              duration_ms=int((time.monotonic() - started) * 1000))
        if res.error is not None:
            self._error_event("forward", res.error)
            self.outcome = "error"