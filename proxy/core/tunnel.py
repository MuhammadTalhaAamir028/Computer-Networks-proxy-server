"""proxy/core/tunnel.py -- HTTPS CONNECT tunnel. Bytes are relayed, never inspected.

Flow:
    send "200 Connection established" -> flush leftover client bytes to the website
    -> relay both directions with selectors -> half-close aware -> idle timeout
"""
import selectors
import socket
import time
from dataclasses import dataclass

FLUSH_BYTES = 64 * 1024
CONNECT_OK = b"HTTP/1.1 200 Connection established\r\n\r\n"


@dataclass
class TunnelResult:
    bytes_up: int = 0        # client -> website
    bytes_down: int = 0      # website -> client
    reason: str = "error"    # client_closed | upstream_closed | idle_timeout | error


def _shutdown_write(sock):
    try:
        sock.shutdown(socket.SHUT_WR)
    except OSError:
        pass


def run_tunnel(client, upstream, *, conn_id, client_ip, host, port, ip, leftover,
               idle_timeout, stats, logger, registry) -> TunnelResult:
    """Run one tunnel to completion. Never raises; the reason says how it ended."""
    started = time.monotonic()
    res = TunnelResult()
    pending_up = pending_down = 0
    first_eof = None

    registry.add(conn_id, client_ip, host, port, ip)
    logger.event("tunnel_open", conn_id=conn_id, host=host, port=port, ip=ip)
    sel = selectors.DefaultSelector()
    try:
        client.settimeout(idle_timeout)
        upstream.settimeout(idle_timeout)
        client.sendall(CONNECT_OK)
        if leftover:                                   # early client bytes go first
            upstream.sendall(leftover)
            res.bytes_up += len(leftover)
            pending_up += len(leftover)
        sel.register(client, selectors.EVENT_READ, "client")
        sel.register(upstream, selectors.EVENT_READ, "upstream")
        last_activity = time.monotonic()

        while len(sel.get_map()) > 0:
            wait = idle_timeout - (time.monotonic() - last_activity)
            if wait <= 0:
                res.reason = "idle_timeout"
                break
            events = sel.select(timeout=wait)
            if not events:
                continue                               # loop re-checks the idle clock
            for key, _mask in events:
                src = key.fileobj
                dst = upstream if src is client else client
                data = src.recv(65536)
                if not data:                           # EOF: half-close the other side
                    sel.unregister(src)
                    _shutdown_write(dst)
                    first_eof = first_eof or key.data
                    continue
                dst.sendall(data)
                last_activity = time.monotonic()
                if src is client:
                    res.bytes_up += len(data)
                    pending_up += len(data)
                else:
                    res.bytes_down += len(data)
                    pending_down += len(data)
                registry.update(conn_id, res.bytes_up, res.bytes_down)
                if pending_up >= FLUSH_BYTES:
                    stats.inc("bytes_up", pending_up)
                    pending_up = 0
                if pending_down >= FLUSH_BYTES:
                    stats.inc("bytes_down", pending_down)
                    pending_down = 0
        else:
            res.reason = "client_closed" if first_eof == "client" else "upstream_closed"
    except socket.timeout:
        res.reason = "idle_timeout"
    except OSError:
        res.reason = "error"
    finally:
        sel.close()
        if pending_up:
            stats.inc("bytes_up", pending_up)
        if pending_down:
            stats.inc("bytes_down", pending_down)
        registry.remove(conn_id)
        logger.event("tunnel_close", conn_id=conn_id, host=host, port=port,
                     bytes_up=res.bytes_up, bytes_down=res.bytes_down,
                     duration_ms=int((time.monotonic() - started) * 1000),
                     reason=res.reason)
    return res