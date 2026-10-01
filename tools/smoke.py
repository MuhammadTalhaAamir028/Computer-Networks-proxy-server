"""Quick PASS/FAIL checks against a running proxy.

Usage:
    python tools/smoke.py --proxy 127.0.0.1:8080
    python tools/smoke.py --proxy 127.0.0.1:8080 --auth alice:S3cr3tPass   (login enabled)

The test origin servers (tools/origin.py) must be running. Exit code is 0 when
nothing failed and 1 otherwise, so CI or a Makefile can use it directly.
"""
from __future__ import annotations

import argparse
import base64
import http.client
import json
import socket
import ssl
import sys
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple

# Seconds we wait for any single network step before calling the check failed.
TIMEOUT = 10.0

# Longest CONNECT reply head we accept (same size as the proxy's header limit).
MAX_HEAD = 16384

# Bytes sent through the tunnel; the TLS echo server must send the same back.
PAYLOAD = b"smoke-test-echo"

# What GET /chunked returns: five pieces, decoded and joined by http.client.
CHUNKED_BODY = b"".join(f"chunk {i}\n".encode() for i in range(1, 6))


@dataclass
class Setup:
    """Everything a check needs to know about the running system."""

    proxy_host: str
    proxy_port: int
    http_host: str  # the test origin (plain HTTP)
    http_port: int
    tls_host: str  # the TLS echo server
    tls_port: int
    blocked_host: str  # a domain the proxy's rules must refuse
    auth_value: Optional[str] = None  # full "Basic ..." header value, or None


@dataclass
class Result:
    """Outcome of one check."""

    name: str
    status: str  # "PASS", "FAIL" or "SKIP"
    detail: str = ""


def parse_hostport(text: str) -> Tuple[str, int]:
    """Split 'host:port' into (host, port); raise ValueError if it is malformed."""
    # rpartition splits on the LAST colon, so the port is always what follows it.
    host, sep, port = text.rpartition(":")
    # Valid TCP port numbers are 1 to 65535.
    if not sep or not host or not port.isdigit() or not 1 <= int(port) <= 65535:
        raise ValueError(f"expected host:port, got {text!r}")
    return host, int(port)


def expect(condition: bool, message: str) -> None:
    """Fail the current check with `message` unless condition is true."""
    # Explicit raise instead of `assert`, which Python skips when run with -O.
    if not condition:
        raise AssertionError(message)


def proxy_get(setup: Setup, url: str,
              send_auth: bool = True) -> Tuple[int, Dict[str, str], bytes]:
    """GET a full URL through the proxy; return (status, lower-cased headers, body)."""
    headers: Dict[str, str] = {}
    if send_auth and setup.auth_value:
        headers["Proxy-Authorization"] = setup.auth_value
    conn = http.client.HTTPConnection(setup.proxy_host, setup.proxy_port, timeout=TIMEOUT)
    try:
        # Giving http.client a full URL makes it send "GET http://host:port/path",
        # which is exactly how a browser talks to a forward proxy.
        conn.request("GET", url, headers=headers)
        resp = conn.getresponse()
        reply_headers = {k.lower(): v for k, v in resp.getheaders()}
        return resp.status, reply_headers, resp.read()
    finally:
        conn.close()


def origin_url(setup: Setup, path: str) -> str:
    """Full URL of a route on the test origin."""
    return f"http://{setup.http_host}:{setup.http_port}{path}"


def read_head(sock: socket.socket) -> bytes:
    """Read one byte at a time until the blank line that ends an HTTP head."""
    # One byte at a time so we never swallow the first bytes of the TLS
    # handshake that may follow the proxy's "200 Connection established".
    data = b""
    while not data.endswith(b"\r\n\r\n"):
        chunk = sock.recv(1)
        expect(bool(chunk), "proxy closed the connection before replying")
        data += chunk
        expect(len(data) <= MAX_HEAD, "proxy reply head is too large")
    return data


def recv_exact(sock: socket.socket, count: int) -> bytes:
    """Receive up to `count` bytes, stopping early only if the peer closes."""
    data = b""
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            break
        data += chunk
    return data


# --------------------------------------------------------------------------
# The checks. Each returns a short detail text on success and raises
# AssertionError (via expect) or any other exception on failure.
# --------------------------------------------------------------------------

def check_root(setup: Setup) -> str:
    """Plain GET / through the proxy reaches the origin."""
    status, _, body = proxy_get(setup, origin_url(setup, "/"))
    expect(status == 200, f"expected 200, got {status}")
    expect(body == b"origin ok", f"unexpected body {body[:40]!r}")
    return "200, body 'origin ok'"


def check_not_found(setup: Setup) -> str:
    """The origin's 404 is passed back unchanged."""
    status, _, _ = proxy_get(setup, origin_url(setup, "/404"))
    expect(status == 404, f"expected 404, got {status}")
    return "404 passed through"


def check_chunked(setup: Setup) -> str:
    """A chunked response arrives complete and readable."""
    status, _, body = proxy_get(setup, origin_url(setup, "/chunked"))
    expect(status == 200, f"expected 200, got {status}")
    expect(body == CHUNKED_BODY, f"chunks did not arrive intact: {body[:60]!r}")
    return "5 chunks received"


def check_request_line_rewritten(setup: Setup) -> str:
    """The origin must see '/echo', not the full URL the browser sent the proxy."""
    status, _, body = proxy_get(setup, origin_url(setup, "/echo"))
    expect(status == 200, f"expected 200, got {status}")
    seen = json.loads(body)["path"]
    expect(seen == "/echo", f"origin saw request target {seen!r}, expected '/echo'")
    return f"origin saw path {seen}"


def check_connect_tls_echo(setup: Setup) -> str:
    """CONNECT to the TLS echo server, do a real handshake, echo some bytes."""
    target = f"{setup.tls_host}:{setup.tls_port}"
    lines = [f"CONNECT {target} HTTP/1.1", f"Host: {target}"]
    if setup.auth_value:
        lines.append(f"Proxy-Authorization: {setup.auth_value}")
    request = ("\r\n".join(lines) + "\r\n\r\n").encode("ascii")
    with socket.create_connection((setup.proxy_host, setup.proxy_port),
                                  timeout=TIMEOUT) as raw:
        raw.sendall(request)
        status_line = read_head(raw).split(b"\r\n", 1)[0].decode("latin-1")
        expect(" 200" in status_line, f"CONNECT reply was {status_line!r}")
        # The test certificate is self-signed, so switch verification off here.
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with context.wrap_socket(raw, server_hostname="localhost") as tls:
            version = tls.version()  # read now: unavailable once the socket closes
            tls.sendall(PAYLOAD)
            echoed = recv_exact(tls, len(PAYLOAD))
    expect(echoed == PAYLOAD, f"echo mismatch: {echoed!r}")
    return f"{version} handshake, echo matched"


def check_blocked_domain(setup: Setup) -> str:
    """A domain on the deny list is refused with 403 (before any connection)."""
    status, _, _ = proxy_get(setup, f"http://{setup.blocked_host}/")
    expect(status == 403, f"expected 403 for {setup.blocked_host}, got {status}")
    return f"403 for {setup.blocked_host}"


def check_auth_required(setup: Setup) -> str:
    """With login enabled, a request without credentials gets 407 and a challenge."""
    status, headers, _ = proxy_get(setup, origin_url(setup, "/"), send_auth=False)
    expect(status == 407, f"expected 407, got {status}")
    expect("proxy-authenticate" in headers, "407 reply has no Proxy-Authenticate header")
    return "407 with challenge"


# (name shown in the table, function). Order is the order they run in.
CHECKS: List[Tuple[str, Callable[[Setup], str]]] = [
    ("plain GET /", check_root),
    ("GET /404 gives 404", check_not_found),
    ("chunked response", check_chunked),
    ("request line rewritten", check_request_line_rewritten),
    ("CONNECT + TLS echo", check_connect_tls_echo),
    ("blocked domain gives 403", check_blocked_domain),
]
AUTH_CHECK_NAME = "no credentials gives 407"


def run_check(name: str, func: Callable[[Setup], str], setup: Setup) -> Result:
    """Run one check; turn any failure into a FAIL row instead of crashing."""
    try:
        return Result(name, "PASS", func(setup))
    except AssertionError as exc:
        return Result(name, "FAIL", str(exc))
    except Exception as exc:  # noqa: BLE001 - timeouts, refused connections, bad JSON...
        return Result(name, "FAIL", f"{type(exc).__name__}: {exc}")


def run_all(setup: Setup) -> List[Result]:
    """Run every check and return the results in order."""
    results = [run_check(name, func, setup) for name, func in CHECKS]
    if setup.auth_value is None:
        results.append(Result(AUTH_CHECK_NAME, "SKIP", "login not enabled (no --auth given)"))
    else:
        results.append(run_check(AUTH_CHECK_NAME, check_auth_required, setup))
    return results


def format_table(results: List[Result]) -> str:
    """Build the PASS/FAIL table as text, with a summary line at the end."""
    width = max(len(r.name) for r in results)  # widest check name sets column 1
    rows = [f"{'CHECK':<{width}}  RESULT  DETAIL", "-" * (width + 40)]
    rows += [f"{r.name:<{width}}  {r.status:<6}  {r.detail}" for r in results]
    counts = {s: sum(r.status == s for r in results) for s in ("PASS", "FAIL", "SKIP")}
    rows.append(f"{counts['PASS']} passed, {counts['FAIL']} failed, {counts['SKIP']} skipped")
    return "\n".join(rows)


def build_setup(args: argparse.Namespace) -> Setup:
    """Turn parsed command-line options into a Setup."""
    proxy_host, proxy_port = parse_hostport(args.proxy)
    http_host, http_port = parse_hostport(args.origin)
    tls_host, tls_port = parse_hostport(args.tls_origin)
    auth_value = None
    if args.auth:
        # "user:pass" becomes the standard Basic header value (base64 of the pair).
        auth_value = "Basic " + base64.b64encode(args.auth.encode("utf-8")).decode("ascii")
    return Setup(proxy_host, proxy_port, http_host, http_port, tls_host, tls_port,
                 args.blocked_host, auth_value)


def main(argv: Optional[List[str]] = None) -> int:
    """Command-line entry point; returns the process exit code."""
    parser = argparse.ArgumentParser(description="Smoke checks against a running proxy")
    parser.add_argument("--proxy", default="127.0.0.1:8080", help="proxy host:port")
    parser.add_argument("--origin", default="127.0.0.1:9000", help="test HTTP origin")
    parser.add_argument("--tls-origin", default="127.0.0.1:9443", help="test TLS echo server")
    parser.add_argument("--blocked-host", default="blocked.example.com",
                        help="a domain listed in filter.deny_domains of the proxy config")
    parser.add_argument("--auth", metavar="USER:PASS",
                        help="proxy login; also turns on the 407 check")
    args = parser.parse_args(argv)
    try:
        setup = build_setup(args)
    except ValueError as exc:
        parser.error(str(exc))  # prints usage and exits with code 2
    results = run_all(setup)
    print(format_table(results))  # this is a command-line tool, so print is allowed
    return 1 if any(r.status == "FAIL" for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())