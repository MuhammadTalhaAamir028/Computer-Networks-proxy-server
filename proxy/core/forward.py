"""proxy/core/forward.py -- plain HTTP forwarding (no keep-alive, always Connection: close).

Flow:
    client request head  -> rewrite -> website
    client body          -> streamed (Content-Length only) -> website
    website response head-> strip hop-by-hop headers -> client
    website response body-> relayed raw until the website closes
"""
import socket
from dataclasses import dataclass
from typing import Optional

from .errors import HttpError

FLUSH_BYTES = 64 * 1024
REQUEST_STRIP = {"connection", "proxy-connection", "keep-alive", "proxy-authorization",
                 "proxy-authenticate", "te", "trailer", "transfer-encoding", "upgrade",
                 "expect", "host"}
RESPONSE_STRIP = {"connection", "proxy-connection", "keep-alive", "proxy-authenticate",
                  "te", "trailer", "upgrade"}


@dataclass
class ForwardResult:
    """What happened. `started` = response bytes already reached the client."""
    status: int = 0
    bytes_up: int = 0
    bytes_down: int = 0
    started: bool = False
    error: Optional[BaseException] = None


class _Counter:
    """Batches byte counts so stats.inc is not called for every chunk."""

    def __init__(self, stats, name):
        self.stats, self.name, self.total, self._pending = stats, name, 0, 0

    def add(self, n):
        self.total += n
        self._pending += n
        if self._pending >= FLUSH_BYTES:
            self.flush()

    def flush(self):
        if self._pending:
            self.stats.inc(self.name, self._pending)
            self._pending = 0


def _names_in_connection(value: str):
    return {p.strip().lower() for p in value.split(",") if p.strip()}


def _host_header(host: str, port: int) -> str:
    shown = f"[{host}]" if ":" in host else host
    return shown if port == 80 else f"{shown}:{port}"


def build_upstream_head(req) -> bytes:
    """Rewrite the client's head into an origin-form HTTP/1.1 request."""
    strip = set(REQUEST_STRIP) | _names_in_connection(req.headers.get("connection", ""))
    lines = [f"{req.method} {req.path} HTTP/1.1", f"Host: {_host_header(req.host, req.port)}"]
    for name, value in req.headers.items():
        if name not in strip:
            lines.append(f"{name}: {value}")
    lines.append("Connection: close")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")


def _read_response_head(upstream, max_bytes: int):
    """Read the website's status line + headers. Returns (head_bytes, leftover)."""
    data = b""
    while b"\r\n\r\n" not in data:
        if len(data) > max_bytes:
            raise HttpError(502, "website response head too large")
        try:
            chunk = upstream.recv(4096)
        except socket.timeout:
            raise HttpError(504, "website did not answer in time")
        except OSError:
            raise HttpError(502, "connection to website failed")
        if not chunk:
            raise HttpError(502, "website closed before answering")
        data += chunk
    head, _, leftover = data.partition(b"\r\n\r\n")
    return head, leftover


def _rewrite_response_head(head: bytes):
    """Drop hop-by-hop headers, add Connection: close. Returns (new_head, status_code)."""
    lines = head.decode("latin-1").split("\r\n")
    parts = lines[0].split(" ", 2)
    if len(parts) < 2 or not parts[0].startswith("HTTP/") or not parts[1].isdigit():
        raise HttpError(502, "invalid response from website")
    status = int(parts[1])
    named = set()
    for ln in lines[1:]:
        if ln.lower().startswith("connection:"):
            named |= _names_in_connection(ln.partition(":")[2])
    strip = RESPONSE_STRIP | named
    kept, keep_prev = [lines[0]], True
    for ln in lines[1:]:
        if ln[:1] in (" ", "\t"):                      # continuation of previous header
            if keep_prev:
                kept.append(ln)
            continue
        keep_prev = ln.partition(":")[0].strip().lower() not in strip
        if keep_prev:
            kept.append(ln)
    kept.append("Connection: close")
    return ("\r\n".join(kept) + "\r\n\r\n").encode("latin-1"), status


def forward_http(client, upstream, req, stats, max_header_bytes: int = 16384) -> ForwardResult:
    """Forward one request and relay the answer. Raises HttpError only BEFORE the
    client has received any response byte; afterwards errors are recorded in the result."""
    result = ForwardResult()
    up, down = _Counter(stats, "bytes_up"), _Counter(stats, "bytes_down")
    try:
        # --- 100-continue: tell the client to send its body ---
        if req.expect_continue:
            client.sendall(b"HTTP/1.1 100 Continue\r\n\r\n")

        # --- request head, then body streamed (leftover first) ---
        head = build_upstream_head(req)
        upstream.sendall(head)
        up.add(len(head))
        remaining = req.content_length
        first = req.leftover[:remaining]
        if first:
            upstream.sendall(first)
            up.add(len(first))
            remaining -= len(first)
        while remaining > 0:
            chunk = client.recv(min(65536, remaining))
            if not chunk:
                raise HttpError(400, "client closed before sending the whole body")
            upstream.sendall(chunk)
            up.add(len(chunk))
            remaining -= len(chunk)

        # --- response head ---
        raw_head, leftover = _read_response_head(upstream, max_header_bytes)
        new_head, result.status = _rewrite_response_head(raw_head)
        client.sendall(new_head)
        result.started = True
        down.add(len(new_head))

        # --- response body: raw relay until the website closes ---
        if leftover:
            client.sendall(leftover)
            down.add(len(leftover))
        while True:
            chunk = upstream.recv(65536)
            if not chunk:
                break
            client.sendall(chunk)
            down.add(len(chunk))
    except OSError as exc:                               # reset / timeout mid-way
        if not result.started:
            if isinstance(exc, socket.timeout):
                raise HttpError(504, "website did not answer in time")
            raise HttpError(502, "connection to website failed")
        result.error = exc
    finally:
        up.flush()
        down.flush()
        result.bytes_up, result.bytes_down = up.total, down.total
    return result