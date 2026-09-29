"""Thread-safe counters for the proxy (implements the Stats contract)."""
from __future__ import annotations

import threading
from typing import Dict

# STAT_KEYS is the frozen list of six counter names from the shared contract
# (requests_total, requests_blocked, active_conns, bytes_up, bytes_down, errors).
# We import it instead of retyping it so we can never drift from the contract.
from ..interfaces import STAT_KEYS


class ThreadSafeStats:
    """Counters that many client threads can update at the same time."""

    def __init__(self) -> None:
        # One lock guards the whole dictionary. Without it, two threads doing
        # "read value, add 1, write value" at the same moment can overwrite each
        # other and lose an increment (a race condition).
        self._lock = threading.Lock()

        # Start every frozen key at 0 so snapshot() always contains all six,
        # even before anything has been counted.
        self._counters: Dict[str, int] = {key: 0 for key in STAT_KEYS}

    def inc(self, name: str, n: int = 1) -> None:
        """Add n to counter `name`; n may be negative (used by the active_conns gauge)."""
        # Public methods must never crash the server (hard rule 4), so silently
        # ignore a name that is not text or an amount that is not a whole number.
        if not isinstance(name, str) or not isinstance(n, int):
            return

        # `with self._lock` takes the lock and always releases it afterwards,
        # even if an error happens inside the block.
        with self._lock:
            # .get(name, 0) means: an unknown counter name starts from 0.
            # This is how "extra names are allowed" from the contract works.
            self._counters[name] = self._counters.get(name, 0) + n

    def snapshot(self) -> dict:
        """Return a copy of all counters, safe for the caller to keep or change."""
        with self._lock:
            # dict(...) makes a copy. If we returned self._counters itself, the
            # caller could edit our real numbers, or see them change mid-read.
            return dict(self._counters)


def build_stats() -> ThreadSafeStats:
    """Factory used by proxy/__main__.py (fixed name from the contract, A6.3)."""
    return ThreadSafeStats()