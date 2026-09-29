"""Local test origin: an HTTP website plus a TLS echo server. TEST ONLY.

Run:  python tools/origin.py --http-port 9000 --tls-port 9443
Binds 127.0.0.1 only. Used by proxy tests, smoke checks and load tests.
"""
from __future__ import annotations

import argparse
import json
import socket
import ssl
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Optional
from urllib.parse import parse_qs, urlsplit

HOST = "127.0.0.1"
FIXTURES = Path(__file__).resolve().parent.parent / "tests" / "fixtures"
MAX_SLOW_MS = 60000
MAX_BIG_MB = 200
MAX_DROP_AFTER = 10 * 1024 * 1024
DROP_DECLARED = 100 * 1024 * 1024
BLOCK = bytes(range(256)) * 256  # 64 KiB deterministic block
REUSE_ADDR = sys.platform != "win32"  # on Windows SO_REUSEADDR allows double binds


class OriginStats:
    """Thread-safe counters served at /__stats."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._c = {"http_requests": 0, "http_connections": 0, "tls_connections": 0}

    def inc(self, name: str) -> None:
        """Add one to a counter."""
        with self._lock:
            self._c[name] += 1

    def snapshot(self) -> dict:
        """Return a copy of all counters."""
        with self._lock:
            return dict(self._c)


def _int_arg(query: dict, name: str, default: int, low: int, high: int) -> Optional[int]:
    """Read an integer query argument clamped to [low, high]; None if not an integer."""
    raw = query.get(name, [None])[0]
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError:
        return None
    return max(low, min(high, value))


class OriginHandler(BaseHTTPRequestHandler):
    """Routes described in the brief (B4). HTTP/1.1 keep-alive is supported."""

    protocol_version = "HTTP/1.1"
    server_version = "TestOrigin/1.0"

    def setup(self) -> None:
        """Count every accepted TCP connection."""
        super().setup()
        self.server.stats.inc("http_connections")  # type: ignore[attr-defined]

    def handle(self) -> None:
        """Ignore clients that vanish mid-request."""
        try:
            super().handle()
        except OSError:
            pass

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        """Silence per-request access logs."""

    def do_GET(self) -> None:  # noqa: N802
        """Handle GET."""
        self._route()

    def do_POST(self) -> None:  # noqa: N802
        """Handle POST."""
        self._route()

    def _route(self) -> None:
        parts = urlsplit(self.path)
        path, query = parts.path, parse_qs(parts.query)
        body_len = self._consume_body()
        if path == "/__stats":
            self._json(200, self.server.stats.snapshot())  # type: ignore[attr-defined]
            return
        self.server.stats.inc("http_requests")  # type: ignore[attr-defined]
        if body_len is None:
            self._json(400, {"error": "bad content-length"})
        elif path == "/":
            self._send(200, b"origin ok")
        elif path == "/404":
            self._send(404, b"not found")
        elif path.startswith("/status/"):
            self._status(path[len("/status/"):])
        elif path == "/slow":
            self._slow(query)
        elif path == "/big":
            self._big(query)
        elif path == "/chunked":
            self._chunked()
        elif path == "/echo":
            self._echo(body_len)
        elif path == "/drop":
            self._drop(query)
        else:
            self._json(404, {"error": "unknown route"})

    def _consume_body(self) -> Optional[int]:
        """Read and discard the request body; return its length (None if invalid)."""
        raw = self.headers.get("Content-Length")
        if raw is None:
            return 0
        try:
            remaining = int(raw)
        except ValueError:
            return None
        if remaining < 0:
            return None
        total = 0
        while remaining > 0:
            chunk = self.rfile.read(min(remaining, 65536))
            if not chunk:
                break
            total += len(chunk)
            remaining -= len(chunk)
        return total

    def _send(self, status: int, body: bytes, ctype: str = "text/plain; charset=utf-8") -> None:
        if status in (204, 304):
            body = b""
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _json(self, status: int, payload: dict) -> None:
        data = json.dumps(payload).encode("utf-8")
        self._send(status, data, "application/json")

    def _status(self, raw: str) -> None:
        try:
            code = int(raw)
        except ValueError:
            code = 0
        if not 200 <= code <= 599:
            self._json(400, {"error": "status must be 200-599"})
            return
        self._send(code, f"status {code}".encode("utf-8"))

    def _slow(self, query: dict) -> None:
        ms = _int_arg(query, "ms", 1000, 0, MAX_SLOW_MS)
        if ms is None:
            self._json(400, {"error": "ms must be an integer"})
            return
        time.sleep(ms / 1000)
        self._send(200, b"slow ok")

    def _big(self, query: dict) -> None:
        mb = _int_arg(query, "mb", 1, 1, MAX_BIG_MB)
        if mb is None:
            self._json(400, {"error": "mb must be an integer"})
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(mb * 1024 * 1024))
        self.end_headers()
        for _ in range(mb * 1024 * 1024 // len(BLOCK)):
            self.wfile.write(BLOCK)

    def _chunked(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        for i in range(1, 6):
            data = f"chunk {i}\n".encode("utf-8")
            self.wfile.write(f"{len(data):X}\r\n".encode("ascii") + data + b"\r\n")
            if i < 5:
                time.sleep(0.1)
        self.wfile.write(b"0\r\n\r\n")

    def _echo(self, body_len: int) -> None:
        payload: dict = {
            "method": self.command,
            "path": self.path,
            "headers": {k.lower(): v for k, v in self.headers.items()},
        }
        if self.command == "POST":
            payload["body_length"] = body_len
        self._json(200, payload)

    def _drop(self, query: dict) -> None:
        after = _int_arg(query, "after", 0, 0, MAX_DROP_AFTER)
        if after is None:
            self._json(400, {"error": "after must be an integer"})
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(DROP_DECLARED))
        self.end_headers()
        sent = 0
        while sent < after:
            piece = BLOCK[: min(len(BLOCK), after - sent)]
            self.wfile.write(piece)
            sent += len(piece)
        self.close_connection = True
        try:
            self.connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass


class _HttpServer(ThreadingHTTPServer):
    """Threaded HTTP server with a backlog big enough for load tests."""

    request_queue_size = 512
    allow_reuse_address = REUSE_ADDR
    daemon_threads = True


class OriginServers:
    """Starts and stops the HTTP origin and the TLS echo server."""

    def __init__(self, http_port: int = 9000, tls_port: Optional[int] = 9443,
                 cert: Optional[Path] = None, key: Optional[Path] = None) -> None:
        self.stats = OriginStats()
        self.http_port = http_port
        self.tls_port = tls_port
        self._cert = cert or FIXTURES / "test_cert.pem"
        self._key = key or FIXTURES / "test_key.pem"
        self._http: Optional[_HttpServer] = None
        self._tls_sock: Optional[socket.socket] = None
        self._ctx: Optional[ssl.SSLContext] = None
        self._stop = threading.Event()
        self._threads: list = []

    def start(self) -> None:
        """Bind both ports and start serving in background threads."""
        self._http = _HttpServer((HOST, self.http_port), OriginHandler)
        self._http.stats = self.stats  # type: ignore[attr-defined]
        self.http_port = self._http.server_address[1]
        self._spawn(self._http.serve_forever)
        if self.tls_port is not None:
            self._start_tls()

    def stop(self) -> None:
        """Stop both servers and release the ports."""
        self._stop.set()
        if self._http is not None:
            self._http.shutdown()
            self._http.server_close()
        if self._tls_sock is not None:
            self._tls_sock.close()
        for thread in self._threads:
            thread.join(timeout=2)

    def _spawn(self, target, *args) -> None:
        thread = threading.Thread(target=target, args=args, daemon=True)
        thread.start()
        self._threads.append(thread)

    def _start_tls(self) -> None:
        self._ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._ctx.load_cert_chain(str(self._cert), str(self._key))
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if REUSE_ADDR:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((HOST, self.tls_port or 0))
        sock.listen(512)
        sock.settimeout(0.5)
        self.tls_port = sock.getsockname()[1]
        self._tls_sock = sock
        self._spawn(self._accept_loop)

    def _accept_loop(self) -> None:
        assert self._tls_sock is not None
        while not self._stop.is_set():
            try:
                conn, _ = self._tls_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            self.stats.inc("tls_connections")
            self._spawn(self._echo, conn)

    def _echo(self, conn: socket.socket) -> None:
        """Handshake, then send every received byte straight back."""
        assert self._ctx is not None
        try:
            conn.settimeout(60)
            with self._ctx.wrap_socket(conn, server_side=True) as tls:
                while True:
                    data = tls.recv(4096)
                    if not data:
                        break
                    tls.sendall(data)
        except OSError:
            pass
        finally:
            conn.close()


def main(argv: Optional[list] = None) -> int:
    """Command-line entry point."""
    parser = argparse.ArgumentParser(description="Local test origin servers (TEST ONLY)")
    parser.add_argument("--http-port", type=int, default=9000)
    parser.add_argument("--tls-port", type=int, default=9443)
    args = parser.parse_args(argv)
    servers = OriginServers(args.http_port, args.tls_port)
    if not (servers._cert.exists() and servers._key.exists()):
        print(f"Missing test certificate in {FIXTURES}. Run: python tools/make_test_cert.py")
        return 1
    try:
        servers.start()
    except OSError as exc:
        print(f"Could not start origin servers: {exc}")
        return 1
    print(f"HTTP origin  : http://{HOST}:{servers.http_port}/")
    print(f"TLS echo     : {HOST}:{servers.tls_port}")
    print("Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        servers.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())