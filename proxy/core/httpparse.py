"""proxy/core/httpparse.py -- turns raw bytes from a client into a request we understand.

Pipeline (each stage is one function):
    STAGE 1  read_head()      -> collect bytes until the blank line (with a deadline)
    STAGE 2  parse_head()     -> split the head into method / target / headers
    STAGE 3  (inside parse)   -> reject garbage: bad request line, bad headers, bad body rules
    STAGE 4  _extract_target()-> work out host, port, path from the target
"""
import re
import socket
import time
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlsplit

from .errors import HttpError

MAX_HEADER_LINES = 100
_METHOD_RE = re.compile(r"^[A-Z]+$")
_VERSION_RE = re.compile(r"^HTTP/1\.\d$")


# ============================================================
# PART 0: DATA SHAPES
# What the rest of the proxy receives from this file.
# ============================================================

class BadRequest(HttpError):
    """Raised when the client sends something invalid.

    status  = HTTP code we reply with (400 bad request, 501 unsupported, 408 timeout)
    message = short human-readable reason
    """

    def __init__(self, status=400, message="Bad Request"):
        super().__init__(status, message)


@dataclass
class ParsedRequest:
    """A clean, validated request. Session code uses only this."""
    method: str                                   # GET, POST, CONNECT ...
    host: str                                     # website we must reach
    port: int                                     # 80 for http, or whatever CONNECT says
    path: Optional[str]                           # "/a?x=1"; None for CONNECT
    version: str                                  # "HTTP/1.1"
    headers: dict = field(default_factory=dict)   # header names in lowercase
    leftover: bytes = b""                         # extra bytes read after the blank line
    content_length: int = 0                       # request body size (0 = no body)
    expect_continue: bool = False                 # client sent "Expect: 100-continue"


# ============================================================
# STAGE 1: READ THE HEAD
# Collect bytes from the socket until \r\n\r\n (blank line).
# Survives: bytes arriving 1 at a time, oversized heads, slow clients (slow-loris).
# ============================================================

def read_head(sock, max_bytes: int = 16384, timeout: float = 30.0):
    """Read until the blank line. Returns (head, leftover).

    `timeout` is an overall deadline for the WHOLE head, not per recv,
    so a client sending one byte per second is dropped at the deadline (408).
    """
    deadline = time.monotonic() + timeout
    data = b""
    while b"\r\n\r\n" not in data:
        if len(data) > max_bytes:
            raise BadRequest(400, "request head too large")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise BadRequest(408, "timed out waiting for the request")
        if hasattr(sock, "settimeout"):
            sock.settimeout(remaining)
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            raise BadRequest(408, "timed out waiting for the request")
        if not chunk:                       # client hung up early
            raise BadRequest(400, "connection closed before the request was complete")
        data += chunk
    head, _, leftover = data.partition(b"\r\n\r\n")
    if len(head) + 4 > max_bytes:
        raise BadRequest(400, "request head too large")
    return head + b"\r\n\r\n", leftover


# ============================================================
# STAGE 2 + 3: PARSE AND VALIDATE THE HEAD
# ============================================================

def parse_head(head: bytes) -> ParsedRequest:
    """Turn a complete head (ending in \\r\\n\\r\\n) into a ParsedRequest."""

    # --- STAGE 3a: no control characters anywhere (NUL etc). Tab is allowed. ---
    text = head.decode("latin-1")
    if any((ord(c) < 32 and c not in "\r\n\t") or ord(c) == 127 for c in text):
        raise BadRequest(400, "control characters in request")

    # --- STAGE 2a: split request line from header lines ---
    lines = text.rstrip("\r\n").split("\r\n")
    if any("\n" in ln or "\r" in ln for ln in lines):
        raise BadRequest(400, "bare line ending in request")
    request_line, header_lines = lines[0], lines[1:]

    # --- STAGE 2b + 3b: request line = exactly METHOD TARGET VERSION ---
    parts = request_line.split(" ")
    if len(parts) != 3:
        raise BadRequest(400, "malformed request line")
    method, target, version = parts
    if not _METHOD_RE.match(method):
        raise BadRequest(400, "method must be upper-case letters")
    if not _VERSION_RE.match(version):
        raise BadRequest(400, "only HTTP/1.x is supported")

    # --- STAGE 2c + 3c: headers ---
    headers = _parse_headers(header_lines)

    # --- STAGE 3d: body rules (Content-Length only) ---
    if "transfer-encoding" in headers:
        raise BadRequest(501, "Transfer-Encoding is not supported")
    content_length = 0
    if "content-length" in headers:
        value = headers["content-length"]
        if not (value.isascii() and value.isdigit()):
            raise BadRequest(400, "invalid Content-Length")
        content_length = int(value)

    expect = headers.get("expect", "").lower() == "100-continue"

    # --- STAGE 4: work out host, port, path from the target ---
    host, port, path = _extract_target(method, target)

    return ParsedRequest(method=method, host=host, port=port, path=path,
                         version=version, headers=headers,
                         content_length=content_length, expect_continue=expect)


def _parse_headers(header_lines):
    """Lower-case names into a dict. Rejects malformed lines and smuggling tricks."""
    if len(header_lines) > MAX_HEADER_LINES:
        raise BadRequest(400, "too many header lines")
    headers = {}
    for line in header_lines:
        if line == "":
            continue
        if line[0] in " \t":
            raise BadRequest(400, "obsolete line folding is not allowed")
        name, sep, value = line.partition(":")
        if not sep or not name or name != name.strip() or " " in name or "\t" in name:
            raise BadRequest(400, "malformed header line")
        name, value = name.lower(), value.strip()
        if name in headers:
            if name == "content-length":
                if headers[name] != value:
                    raise BadRequest(400, "conflicting Content-Length headers")
            else:
                headers[name] = headers[name] + ", " + value
        else:
            headers[name] = value
    return headers


# ============================================================
# STAGE 4: EXTRACT THE TARGET
# "http://example.com:8000/a?x=1" -> host, port, path.
# CONNECT "example.com:443" and IPv6 "[::1]:80" are handled too.
# We route ONLY by the target, never by the Host header.
# ============================================================

def _valid_port(text: str) -> int:
    if not (text.isascii() and text.isdigit()) or not 1 <= int(text) <= 65535:
        raise BadRequest(400, "port must be 1 to 65535")
    return int(text)


def _extract_target(method: str, target: str):
    """Work out (host, port, path) from the request target."""

    # --- CONNECT: target is "host:port" or "[v6]:port", no scheme, no path ---
    if method == "CONNECT":
        if "@" in target or "/" in target:
            raise BadRequest(400, "CONNECT target must be host:port")
        if target.startswith("["):
            end = target.find("]")
            host, rest = target[1:end], target[end + 1:]
            if end == -1 or not rest.startswith(":"):
                raise BadRequest(400, "CONNECT target must be [host]:port")
            port_text = rest[1:]
        else:
            host, sep, port_text = target.rpartition(":")
            if not sep:
                raise BadRequest(400, "CONNECT target must be host:port")
        if not host:
            raise BadRequest(400, "CONNECT target has no host")
        return host.lower(), _valid_port(port_text), None

    # --- Plain HTTP: target must be an absolute http:// URL ---
    lowered = target.lower()
    if lowered.startswith("https://"):
        raise BadRequest(400, "HTTPS must use CONNECT")
    if not lowered.startswith("http://"):
        raise BadRequest(400, "an absolute http:// URI is required")
    try:
        parts = urlsplit(target)
        host, port = parts.hostname, parts.port
    except ValueError:
        raise BadRequest(400, "invalid target URI")
    if "@" in parts.netloc:
        raise BadRequest(400, "user info in URI is not allowed")
    if not host:
        raise BadRequest(400, "target has no host")
    if port is None:
        port = 80
    elif not 1 <= port <= 65535:
        raise BadRequest(400, "port must be 1 to 65535")
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    return host, port, path