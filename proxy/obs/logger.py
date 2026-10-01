"""Non-blocking JSON-lines logger (implements the Logger contract)."""
from __future__ import annotations

import atexit
import copy
import json
import logging
import math
import queue
import re
import sys
import threading
import time
from collections import deque
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Deque, Optional

# ---------------------------------------------------------------------------
# Hard-coded values, each with the reason it exists
# ---------------------------------------------------------------------------

# Maximum events waiting to be written. If the disk is slower than the proxy and
# this fills up, new events are dropped (and counted) instead of blocking clients.
QUEUE_MAX = 10000

# Strings longer than this are cut, so one huge value cannot bloat the log file.
MAX_STR = 500

# How deep we follow nested dicts/lists. Stops endless loops if an object
# contains itself (for example a dict that holds a reference to that same dict).
MAX_DEPTH = 8

# What a secret value is replaced with in the log.
REDACTED = "[REDACTED]"

# Key names whose values are secrets. A key is compared lower-cased with "-"
# turned into "_", so "Proxy-Authorization" and "proxy_authorization" both match.
REDACT_KEYS = frozenset({
    "authorization", "proxy_authorization", "password", "passwd", "secret",
    "token", "cookie", "set_cookie", "api_key",
})

# Fields that would hold request/response bodies. The brief says never log
# bodies, so these keys are removed completely instead of being shortened.
BODY_KEYS = frozenset({"body", "request_body", "response_body"})

# ts and kind are written by the logger itself; a caller cannot overwrite them.
RESERVED_KEYS = frozenset({"ts", "kind"})

# Matches "Basic <base64>" or "Bearer <token>" anywhere inside a text value.
# The character list covers base64 (A-Z a-z 0-9 + / =) and common token symbols.
AUTH_PATTERN = re.compile(r"\b(Basic|Bearer)\s+[A-Za-z0-9+/=._~-]+", re.IGNORECASE)

# Same numbers the standard logging module uses, so levels compare correctly.
LEVELS = {"DEBUG": 10, "INFO": 20, "WARNING": 30, "ERROR": 40}

# Event kinds that are not plain INFO. Anything not listed here is INFO.
LEVEL_BY_KIND = {"error": LEVELS["ERROR"], "auth_fail": LEVELS["WARNING"],
                 "req_blocked": LEVELS["WARNING"]}


# ---------------------------------------------------------------------------
# Cleaning helpers: turn any caller value into something safe to write
# ---------------------------------------------------------------------------

def _utc_stamp() -> str:
    """Return now as UTC ISO-8601 with milliseconds and a trailing Z."""
    now = datetime.now(timezone.utc)
    # microsecond // 1000 converts microseconds (0-999999) to milliseconds (0-999);
    # :03d pads to three digits so 5 ms is written as 005.
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"


def _safe_text(value: Any) -> str:
    """Convert to str without ever raising (a broken __str__ must not crash us)."""
    if isinstance(value, str):
        return value
    try:
        return str(value)
    except Exception:  # noqa: BLE001 - any failure here must be swallowed
        return "<unprintable>"


def _safe_repr(value: Any) -> str:
    """Convert to repr without ever raising."""
    try:
        return repr(value)
    except Exception:  # noqa: BLE001
        return "<unrepresentable>"


def _clean_text(text: str) -> str:
    """Cut to MAX_STR characters, then hide any Basic/Bearer credentials."""
    # Cut first (cheap), scrub second. A token cut in half still matches the
    # pattern, so no piece of a credential can survive the cut.
    # \1 keeps the word "Basic"/"Bearer" and only the credential is replaced.
    return AUTH_PATTERN.sub(r"\1 " + REDACTED, text[:MAX_STR])


def _clean_value(value: Any, log_query: bool, depth: int) -> Any:
    """Return a JSON-safe copy of value (recursive for dicts and lists)."""
    if depth > MAX_DEPTH:
        return "<max depth>"
    # None, True/False and whole numbers are already valid JSON.
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        # NaN and infinity are not valid JSON, so write them as text instead.
        return value if math.isfinite(value) else _safe_repr(value)
    if isinstance(value, str):
        return _clean_text(value)
    if isinstance(value, dict):
        return _clean_dict(value, log_query, depth + 1)
    if isinstance(value, (list, tuple)):
        return [_clean_value(item, log_query, depth + 1) for item in value]
    # bytes, sets, custom objects, ...: fall back to repr as the brief says.
    return _clean_text(_safe_repr(value))


def _clean_dict(data: dict, log_query: bool, depth: int) -> dict:
    """Clean a dict: drop body keys, redact secret keys, strip ?query from paths."""
    out: dict = {}
    for key, value in list(data.items()):
        name = _safe_text(key)[:MAX_STR]
        # Normalise for comparison only: "Set-Cookie" -> "set_cookie".
        norm = name.lower().replace("-", "_")
        if norm in BODY_KEYS:
            continue
        if norm in REDACT_KEYS:
            out[name] = REDACTED
            continue
        if norm == "path" and isinstance(value, str) and not log_query:
            value = value.split("?", 1)[0]  # keep everything before the first "?"
        out[name] = _clean_value(value, log_query, depth)
    return out


def _parse_level(level: Any) -> int:
    """Turn a config level name into a number; unknown names fall back to INFO."""
    return LEVELS.get(_safe_text(level).upper(), LEVELS["INFO"])


# ---------------------------------------------------------------------------
# The logger
# ---------------------------------------------------------------------------

# Put on the queue to tell the writer thread to stop.
_STOP = object()


class JsonLogger:
    """Queues events, writes them from one background thread, keeps a ring buffer."""

    def __init__(self, path: Any, max_bytes: int = 5_000_000, backups: int = 3,
                 console: bool = True, level: str = "INFO", ring_size: int = 2000,
                 log_query: bool = False, stats: Any = None,
                 queue_size: int = QUEUE_MAX) -> None:
        self.dropped = 0  # events lost because the queue was full
        self._stats = stats
        self._log_query = log_query
        self._threshold = _parse_level(level)
        # A ring of size 0 would keep nothing, so require at least 1.
        self._ring_size = max(1, int(ring_size))
        # deque(maxlen=N) automatically forgets the oldest item when full.
        self._ring: Deque[dict] = deque(maxlen=self._ring_size)
        self._ring_lock = threading.Lock()  # guards the ring
        self._drop_lock = threading.Lock()  # guards the self.dropped counter
        self._queue: queue.Queue = queue.Queue(maxsize=queue_size)
        self._closed = False
        self._out = self._build_output(path, max_bytes, backups, console)
        # daemon=True: this thread never stops Python from exiting.
        self._thread = threading.Thread(target=self._writer_loop, name="log-writer",
                                        daemon=True)
        self._thread.start()
        atexit.register(self.close)  # flush what is left when the program exits

    def _build_output(self, path: Any, max_bytes: int, backups: int,
                      console: bool) -> logging.Logger:
        """Create a private logging.Logger with the file and console handlers."""
        # Created directly (not via getLogger) so tests can make many of these
        # without them piling up in the global logger registry.
        out = logging.Logger(f"proxy.events.{id(self)}", level=logging.DEBUG)
        # The message is already a finished JSON line, so add nothing around it.
        formatter = logging.Formatter("%(message)s")
        try:
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            # delay=True opens the file on the first write; needed on Windows.
            handler = RotatingFileHandler(str(path), maxBytes=max_bytes,
                                          backupCount=backups, encoding="utf-8",
                                          delay=True)
            handler.setFormatter(formatter)
            out.addHandler(handler)
        except OSError as exc:
            # Never crash the server because of a bad log path; keep going.
            sys.stderr.write(f"logger: cannot use log file {path}: {exc}\n")
        if console:
            console_handler = logging.StreamHandler(sys.stderr)
            console_handler.setFormatter(formatter)
            out.addHandler(console_handler)
        return out

    def event(self, kind: str, **fields: Any) -> None:
        """Record one event. Never raises and never waits for the disk."""
        try:
            if self._closed:
                return
            kind = _safe_text(kind)
            levelno = LEVEL_BY_KIND.get(kind, LEVELS["INFO"])
            if levelno < self._threshold:
                return  # below the configured level: ignore cheaply
            record = {"ts": _utc_stamp(), "kind": kind}
            cleaned = _clean_dict(fields, self._log_query, 0)
            record.update({k: v for k, v in cleaned.items() if k not in RESERVED_KEYS})
            # put_nowait raises queue.Full instead of waiting, so callers never block.
            self._queue.put_nowait((levelno, record))
        except queue.Full:
            self._count_drop()
        except Exception:  # noqa: BLE001 - logging must never break the proxy
            pass

    def _count_drop(self) -> None:
        """Count one lost event (thread-safe) and tell stats if we have one."""
        with self._drop_lock:
            self.dropped += 1
        if self._stats is not None:
            try:
                self._stats.inc("log_dropped")
            except Exception:  # noqa: BLE001
                pass

    def tail(self, n: int = 100) -> list:
        """Return copies of the last n events, newest last (n limited to ring size)."""
        try:
            count = max(0, min(int(n), self._ring_size))
        except (TypeError, ValueError):
            count = 0
        with self._ring_lock:
            # [-0:] would return everything, so handle 0 separately.
            items = list(self._ring)[-count:] if count else []
        # deepcopy outside the lock so callers can edit results without
        # touching our stored events, and so we hold the lock only briefly.
        return copy.deepcopy(items)

    def flush(self, timeout: float = 5.0) -> bool:
        """Wait until every queued event is written. False if it took too long."""
        deadline = time.monotonic() + timeout
        # unfinished_tasks counts items put on the queue but not yet fully handled.
        while self._queue.unfinished_tasks > 0:
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.005)  # 5 ms pause so we do not burn CPU while waiting
        for handler in list(self._out.handlers):
            handler.flush()
        return True

    def close(self) -> None:
        """Write everything still queued, stop the writer thread, close the files."""
        if self._closed:
            return
        self._closed = True  # from now on event() ignores new events
        self.flush()
        try:
            self._queue.put(_STOP, timeout=1)
        except queue.Full:
            pass
        self._thread.join(timeout=2)
        for handler in list(self._out.handlers):
            handler.flush()
            handler.close()
            self._out.removeHandler(handler)
        atexit.unregister(self.close)

    def _writer_loop(self) -> None:
        """Background thread: take events off the queue and write them."""
        while True:
            item = self._queue.get()  # waits here until something arrives
            try:
                if item is _STOP:
                    return
                self._write(item)
            except Exception:  # noqa: BLE001 - a bad event must not kill the writer
                pass
            finally:
                # Always mark the item done, or flush() would wait forever.
                self._queue.task_done()

    def _write(self, item: tuple) -> None:
        """Write one event to the outputs and remember it in the ring buffer."""
        levelno, record = item
        # separators=(",", ":") removes spaces, so each line is compact.
        # ensure_ascii=True writes any non-English character as \\uXXXX, so a stray
        # odd character can never break the file or the Windows console.
        # allow_nan=False makes json refuse NaN instead of writing invalid JSON.
        line = json.dumps(record, separators=(",", ":"), ensure_ascii=True,
                          allow_nan=False)
        self._out.log(levelno, line)
        with self._ring_lock:
            self._ring.append(record)


def build_logger(config: Any, stats: Any = None) -> JsonLogger:
    """Factory used by proxy/__main__.py (fixed name from the contract, A6.3)."""
    # The second argument of each config.get is the default from the config table.
    return JsonLogger(
        path=config.get("logging.file", "logs/proxy.jsonl"),
        max_bytes=config.get("logging.max_bytes", 5000000),
        backups=config.get("logging.backups", 3),
        console=config.get("logging.console", True),
        level=config.get("logging.level", "INFO"),
        ring_size=config.get("logging.ring_size", 2000),
        log_query=config.get("logging.log_query", False),
        stats=stats,
    )