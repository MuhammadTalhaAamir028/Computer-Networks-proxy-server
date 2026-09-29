"""proxy/core/httpparse.py -- turns raw bytes from a client into a request we understand.

Pipeline (each stage is one function, filled in later):
    STAGE 1  read_head()      -> collect bytes until the blank line
    STAGE 2  parse_head()     -> split the head into method / target / headers
    STAGE 3  validate         -> reject garbage (bad request line, bad headers)
    STAGE 4  extract_target() -> work out host, port, path from the target
"""
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlsplit

# ============================================================
# PART 0: DATA SHAPES
# What the rest of the proxy receives from this file.
# ============================================================

class BadRequest(Exception):
    """Raised when the client sends something invalid.

    status  = HTTP code we reply with (400 bad request, 501 unsupported, 408 timeout)
    message = short human-readable reason
    """
    def __init__(self, status=400, message="Bad Request"):
        super().__init__(message)
        self.status = status
        self.message = message


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


# ============================================================
# STAGE 1: READ THE HEAD
# Collect bytes from the socket until \r\n\r\n (blank line).
# Must survive: bytes arriving 1 at a time, oversized heads, slow clients.
# (Function comes later.)
# ============================================================


# ============================================================
# STAGE 2 + 3: PARSE AND VALIDATE THE HEAD
# Split the head into request line + headers, and reject garbage.
# ============================================================

def parse_head(head: bytes) -> ParsedRequest:
    """Turn a complete head (ending in \\r\\n\\r\\n) into a ParsedRequest."""

    # --- STAGE 2a: split request line from header lines ---
    text = head.decode("latin-1")
    lines = text.split("\r\n")
    request_line = lines[0]

    # --- STAGE 2b: split request line into method / target / version ---
    parts = request_line.split(" ")
    if len(parts) != 3:  # STAGE 3: must be exactly 3 parts
        raise BadRequest(400, "malformed request line")
    method, target, version = parts

    # --- STAGE 3: only HTTP/1.0 and HTTP/1.1 are supported ---
    if version not in ("HTTP/1.0", "HTTP/1.1"):
        raise BadRequest(505, "HTTP version not supported")
    # --- STAGE 2d: build the headers dict (lowercase names) ---
    headers = {}
    for line in lines[1:]:
        if line == "":
            break                      # blank line = end of head
        name, _, value = line.partition(":")
        headers[name.strip().lower()] = value.strip()

    # --- STAGE 4: work out host, port, path from the target ---
    host, port, path = _extract_target(method, target)

    return ParsedRequest(method=method, host=host, port=port,
                         path=path, version=version, headers=headers)


# ============================================================
# STAGE 4: EXTRACT THE TARGET
# From "http://example.com:8000/a?x=1" get host, port, path.
# Also handles CONNECT "example.com:443" and IPv6 "[::1]:80".
# (Function comes later.)
# ============================================================

def _extract_target(method: str, target: str):
    """Work out (host, port, path) from the request target."""

    # --- CONNECT: target is "host:port", no scheme, no path ---
    if method == "CONNECT":
        host, sep, port_text = target.rpartition(":")

        # STAGE 3 validation: need a colon, a host, and a numeric port
        if not sep or not host or not port_text.isdigit():
            raise BadRequest(400, "CONNECT target must be host:port")

        port = int(port_text)
        if not 1 <= port <= 65535:
            raise BadRequest(400, "port out of range")

        return host, port, None

    # --- Plain HTTP: target is a full URL ---
    parts = urlsplit(target)
    host = parts.hostname
    port = parts.port or 80            # no port given -> 80
    path = parts.path or "/"           # empty path -> "/"
    if parts.query:
        path += "?" + parts.query      # keep the query
    return host, port, path