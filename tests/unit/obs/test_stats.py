"""Unit tests for proxy/obs/stats.py."""
from __future__ import annotations

import threading

from proxy.interfaces import STAT_KEYS
from proxy.obs.stats import build_stats


def test_concurrent_totals_are_exact():
    stats = build_stats()
    threads_count = 10  # how many threads hammer the counter together
    per_thread = 100_000  # how many increments each thread makes

    def worker() -> None:
        for _ in range(per_thread):
            stats.inc("requests_total")

    threads = [threading.Thread(target=worker) for _ in range(threads_count)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # 10 x 100,000 = 1,000,000. Even one lost increment would fail this test.
    assert stats.snapshot()["requests_total"] == threads_count * per_thread


def test_negative_increment_works_like_a_gauge():
    stats = build_stats()
    stats.inc("active_conns")  # a connection opens: +1
    stats.inc("active_conns")  # another opens: +1
    stats.inc("active_conns", -1)  # one closes: -1
    assert stats.snapshot()["active_conns"] == 1


def test_snapshot_has_all_six_frozen_keys_at_zero():
    snap = build_stats().snapshot()
    assert set(STAT_KEYS) <= set(snap)  # every frozen key is present
    assert all(snap[key] == 0 for key in STAT_KEYS)  # and starts at 0


def test_snapshot_is_a_copy():
    stats = build_stats()
    snap = stats.snapshot()
    snap["requests_total"] = 999  # caller edits their copy...
    assert stats.snapshot()["requests_total"] == 0  # ...real counter is untouched


def test_unknown_names_are_allowed():
    stats = build_stats()
    stats.inc("log_dropped", 3)  # not one of the six frozen keys
    assert stats.snapshot()["log_dropped"] == 3


def test_bad_input_never_raises():
    stats = build_stats()
    stats.inc(None)  # type: ignore[arg-type]
    stats.inc("errors", "five")  # type: ignore[arg-type]
    stats.inc(123, 1)  # type: ignore[arg-type]
    assert stats.snapshot()["errors"] == 0  # nothing was counted, nothing crashed