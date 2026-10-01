"""tests/unit/core/test_tunnel.py -- CONNECT relay: bytes, half-close, idle timeout, registry."""
import socket
import threading

from proxy.core.registry import TunnelRegistry
from proxy.core.tunnel import CONNECT_OK, run_tunnel
from proxy.stubs import MemoryStats
from tests.conftest import RecLogger, wait_for


def start_tunnel(idle_timeout=2.0, leftover=b""):
    """Wire two socketpairs through run_tunnel.

    client_side <-> [proxy_client ==tunnel== proxy_up] <-> site_side
    Returns (client_side, site_side, thread, holder) where holder['res'] gets the result.
    """
    proxy_client, client_side = socket.socketpair()
    proxy_up, site_side = socket.socketpair()
    stats, logger, registry = MemoryStats(), RecLogger(), TunnelRegistry()
    holder = {"stats": stats, "logger": logger, "registry": registry}

    def target():
        holder["res"] = run_tunnel(
            proxy_client, proxy_up, conn_id=1, client_ip="10.0.0.1", host="site.test",
            port=443, ip="1.2.3.4", leftover=leftover, idle_timeout=idle_timeout,
            stats=stats, logger=logger, registry=registry)

    t = threading.Thread(target=target, daemon=True)
    t.start()
    client_side.settimeout(3)
    site_side.settimeout(3)
    return client_side, site_side, t, holder


def test_sends_200_then_relays_both_directions_and_counts_bytes():
    client, site, t, h = start_tunnel()
    assert client.recv(100) == CONNECT_OK
    client.sendall(b"hello-site")
    assert site.recv(100) == b"hello-site"
    site.sendall(b"hello-client!")
    assert client.recv(100) == b"hello-client!"
    client.close()
    site.close()
    t.join(3)
    res = h["res"]
    assert (res.bytes_up, res.bytes_down) == (10, 13)
    snap = h["stats"].snapshot()
    assert (snap["bytes_up"], snap["bytes_down"]) == (10, 13)     # counted exactly once


def test_leftover_bytes_go_upstream_first():
    client, site, t, h = start_tunnel(leftover=b"EARLY")
    assert client.recv(100) == CONNECT_OK
    assert site.recv(100) == b"EARLY"
    client.close(); site.close(); t.join(3)
    assert h["res"].bytes_up == 5


def test_registry_has_the_tunnel_while_open_and_is_empty_after():
    client, site, t, h = start_tunnel()
    client.recv(100)
    client.sendall(b"x")
    site.recv(10)
    # registry.update runs just after the relay's sendall, so poll instead of racing it
    assert wait_for(lambda: h["registry"].snapshot()
                    and h["registry"].snapshot()[0]["bytes_up"] == 1)
    snap = h["registry"].snapshot()
    assert len(snap) == 1 and snap[0]["host"] == "site.test"
    client.close(); site.close(); t.join(3)
    assert h["registry"].snapshot() == []


def test_events_tunnel_open_then_close_with_totals():
    client, site, t, h = start_tunnel()
    client.recv(100)
    client.sendall(b"abc")
    site.recv(10)
    client.close(); site.close(); t.join(3)
    kinds = [e["kind"] for e in h["logger"].events]
    assert kinds == ["tunnel_open", "tunnel_close"]
    close = h["logger"].of("tunnel_close")[0]
    assert close["bytes_up"] == 3 and close["host"] == "site.test"
    assert "ip" in h["logger"].of("tunnel_open")[0]


def test_client_closes_first_reason():
    client, site, t, h = start_tunnel()
    client.recv(100)
    client.close()
    site.settimeout(3)
    assert site.recv(10) == b""              # EOF reaches the website (half-close)
    site.close(); t.join(3)
    assert h["res"].reason == "client_closed"


def test_site_closes_first_reason():
    client, site, t, h = start_tunnel()
    client.recv(100)
    site.close()
    assert client.recv(10) == b""
    client.close(); t.join(3)
    assert h["res"].reason == "upstream_closed"


def test_half_close_still_lets_the_other_direction_finish():
    """Client says 'I'm done sending'; the site may still send its last bytes."""
    client, site, t, h = start_tunnel()
    client.recv(100)
    client.sendall(b"req")
    client.shutdown(socket.SHUT_WR)
    assert site.recv(10) == b"req"
    site.sendall(b"late-reply")
    assert client.recv(20) == b"late-reply"
    site.close(); client.close(); t.join(3)
    assert h["res"].bytes_down == 10


def test_idle_tunnel_times_out():
    client, site, t, h = start_tunnel(idle_timeout=0.4)
    client.recv(100)
    t.join(3)                                 # nobody talks -> must end by itself
    assert not t.is_alive()
    assert h["res"].reason == "idle_timeout"
    assert h["registry"].snapshot() == []
    client.close(); site.close()


def test_large_transfer_is_counted_exactly():
    client, site, t, h = start_tunnel()
    client.recv(100)
    payload = b"z" * 300_000                   # bigger than FLUSH_BYTES (64 KiB) on purpose
    got = bytearray()

    def drain():
        while len(got) < len(payload):
            chunk = site.recv(65536)
            if not chunk:
                break
            got.extend(chunk)

    d = threading.Thread(target=drain)
    d.start()
    client.sendall(payload)
    d.join(5)
    client.close(); site.close(); t.join(3)
    assert len(got) == len(payload)
    assert h["res"].bytes_up == len(payload)
    assert h["stats"].snapshot()["bytes_up"] == len(payload)
