"""proxy/core/registry.py -- thread-safe list of open CONNECT tunnels
 (for the admin /tunnels route)."""
import threading
import time
from datetime import datetime, timezone


class TunnelRegistry:
    """Tracks active tunnels. All methods are safe to call from many threads."""

    def __init__(self):
        self._lock = threading.Lock()
        self._tunnels = {}

    def add(self, conn_id, client_ip, host, port, ip):
        with self._lock:
            self._tunnels[conn_id] = {
                "conn_id": conn_id, "client_ip": client_ip, "host": host,
                "port": port, "ip": ip,
                "started_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "bytes_up": 0, "bytes_down": 0, "_last": time.monotonic(),
            }

    def update(self, conn_id, bytes_up, bytes_down):
        """Record the latest byte totals; resets the idle clock."""
        with self._lock:
            t = self._tunnels.get(conn_id)
            if t is not None:
                t["bytes_up"], t["bytes_down"] = bytes_up, bytes_down
                t["_last"] = time.monotonic()

    def remove(self, conn_id):
        with self._lock:
            self._tunnels.pop(conn_id, None)

    def snapshot(self):
        """Copies, safe to serialise. No secrets exist here."""
        now = time.monotonic()
        with self._lock:
            out = []
            for t in self._tunnels.values():
                row = {k: v for k, v in t.items() if not k.startswith("_")}
                row["idle_s"] = round(now - t["_last"], 1)
                out.append(row)
            return out