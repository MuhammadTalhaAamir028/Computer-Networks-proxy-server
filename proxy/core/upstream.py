"""proxy/core/upstream.py -- find the website and connect to it, safely.

Order of work:
    1. resolve the name          (failure -> 502)
    2. ask the filter about EVERY resolved IP (SSRF guard), keep the allowed ones
    3. refuse targets that point back at the proxy itself (endless loop guard)
    4. connect to a resolved IP (never the name again), up to 3 tries
Known limitation: getaddrinfo has no timeout.
"""
import ipaddress
import socket
from typing import Optional

from ..interfaces import Decision
from .errors import HttpError

MAX_CONNECT_TRIES = 3


class UpstreamError(HttpError):
    """Could not reach the website. `decision` is set when the reason is a 403."""

    def __init__(self, status: int, message: str = "", decision: Optional[Decision] = None):
        super().__init__(status, message)
        self.decision = decision


def _is_self_loop(ip: str, port: int, own_ports, proxy_host: str) -> bool:
    """True if (ip, port) would make the proxy connect to itself."""
    if port not in own_ports:
        return False
    try:
        loopback = ipaddress.ip_address(ip.split("%")[0]).is_loopback
    except ValueError:
        loopback = False
    return loopback or ip == proxy_host


def connect_upstream(host: str, port: int, filt, connect_timeout: float,
                     read_timeout: float, own_ports=(), proxy_host: str = ""):
    """Resolve, check, connect. Returns (socket, ip). Raises UpstreamError."""

    # --- 1: resolve ---
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError, OSError):
        raise UpstreamError(502, "could not resolve host")

    # --- 2 + 3: filter every address, drop self-loops ---
    allowed, first_denial = [], None
    seen = set()
    for family, _type, _proto, _canon, sockaddr in infos:
        ip = sockaddr[0]
        if ip in seen:
            continue
        seen.add(ip)
        decision = filt.check_ip(ip, port)
        if not decision.allowed:
            first_denial = first_denial or decision
            continue
        if _is_self_loop(ip, port, own_ports, proxy_host):
            first_denial = first_denial or Decision(
                False, "target is the proxy itself", rule="self-loop")
            continue
        allowed.append((family, sockaddr, ip))
    if not allowed:
        raise UpstreamError(403, "target address not allowed",
                            decision=first_denial or Decision(False, "blocked"))

    # --- 4: connect, up to three allowed addresses ---
    timeouts = 0
    tries = allowed[:MAX_CONNECT_TRIES]
    for family, sockaddr, ip in tries:
        sock = socket.socket(family, socket.SOCK_STREAM)
        try:
            sock.settimeout(connect_timeout)
            sock.connect(sockaddr)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            sock.settimeout(read_timeout)
            return sock, ip
        except socket.timeout:
            timeouts += 1
            sock.close()
        except OSError:
            sock.close()
    if timeouts == len(tries):
        raise UpstreamError(504, "connection to website timed out")
    raise UpstreamError(502, "could not connect to website")