"""tests/unit/core/test_registry.py -- the live-tunnel list that Phase 2 admin will read."""
import threading

from proxy.core.registry import TunnelRegistry


def test_add_then_snapshot_has_public_fields_only():
    reg = TunnelRegistry()
    reg.add(1, "10.0.0.5", "example.com", 443, "93.184.216.34")
    row = reg.snapshot()[0]
    assert row["conn_id"] == 1
    assert row["host"] == "example.com" and row["port"] == 443
    assert row["bytes_up"] == 0 and row["bytes_down"] == 0
    assert "idle_s" in row
    assert not any(k.startswith("_") for k in row)      # internals never leak


def test_update_changes_byte_totals():
    reg = TunnelRegistry()
    reg.add(1, "10.0.0.5", "example.com", 443, "1.2.3.4")
    reg.update(1, 500, 900)
    row = reg.snapshot()[0]
    assert (row["bytes_up"], row["bytes_down"]) == (500, 900)


def test_remove_deletes_and_is_idempotent():
    reg = TunnelRegistry()
    reg.add(1, "a", "h", 443, "1.1.1.1")
    reg.remove(1)
    reg.remove(1)                                        # second call must not raise
    assert reg.snapshot() == []


def test_update_unknown_id_is_ignored():
    reg = TunnelRegistry()
    reg.update(99, 1, 1)                                 # must not raise
    assert reg.snapshot() == []


def test_snapshot_is_a_copy():
    reg = TunnelRegistry()
    reg.add(1, "a", "h", 443, "1.1.1.1")
    reg.snapshot()[0]["host"] = "tampered"
    assert reg.snapshot()[0]["host"] == "h"


def test_many_threads_add_and_remove_safely():
    reg = TunnelRegistry()

    def work(base):
        for i in range(200):
            reg.add(base + i, "a", "h", 443, "1.1.1.1")
            reg.update(base + i, i, i)
            reg.remove(base + i)

    threads = [threading.Thread(target=work, args=(n * 1000,)) for n in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert reg.snapshot() == []
