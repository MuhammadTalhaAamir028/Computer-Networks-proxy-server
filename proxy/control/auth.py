"""
proxy.control.auth
~~~~~~~~~~~~~~~~~~
Proxy authentication and per-client lockout enforcement for the control layer.

Validates the frozen ``Auth`` protocol from ``proxy.interfaces``:
- Basic ``Proxy-Authorization`` credentials
- scrypt password verification and unknown-user timing protection
- successful-credential caching with reload invalidation
- bounded per-client-IP failure tracking and lockout
- redacted recent-failure history
- complete HTTP 407 and 429 response construction

This module consumes the shared configuration abstraction and never performs
request parsing, destination filtering, DNS resolution, socket operations,
network connections, TLS inspection, or direct logging.

Public API
----------
- ``Authenticator`` - concrete implementation of the frozen ``Auth`` contract
- ``build_auth`` - factory used by ``proxy.control.__init__``
"""
from __future__ import annotations

import base64
import binascii
from collections import OrderedDict, deque
from datetime import datetime, timezone
import hashlib
import hmac
import math
import threading
import time
from typing import Any, Callable, Optional

from proxy.interfaces import AuthResult


# ── bounded authentication state ──────────────────────────────
_MAX_HEADER_LENGTH = 512
_CACHE_TTL = 300.0
_MAX_CACHE_ENTRIES = 1024
_MAX_TRACKED_CLIENTS = 10_000
_MAX_FAILURE_HISTORY = 200
_DUMMY_SALT = b"proxy-auth-dummy-salt"
SCRYPT = {"n": 2**14, "r": 8, "p": 1, "dklen": 32}


def hash_password(password: bytes, salt: bytes) -> bytes:
    """Derive an authentication key using the project's scrypt parameters."""
    return hashlib.scrypt(password, salt=salt, **SCRYPT)


class Authenticator:
    """Validate proxy credentials and enforce per-client lockouts."""

    def __init__(
        self,
        config: Any,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._config = config
        self._clock = clock
        self._state_lock = threading.Lock()
        self._cache_lock = threading.Lock()
        self._cache: OrderedDict[bytes, tuple[str, float]] = OrderedDict()
        self._failures: OrderedDict[str, tuple[deque[float], float]] = (
            OrderedDict()
        )
        self._history: deque[dict[str, Any]] = deque(
            maxlen=_MAX_FAILURE_HISTORY
        )
        self._settings_lock = threading.Lock()
        self._dummy_digest = hash_password(b"\x00dummy", _DUMMY_SALT)
        self._load_settings()

        add_listener = getattr(config, "add_reload_listener", None)
        if callable(add_listener):
            add_listener(self._on_config_reload)

    def _load_settings(self) -> None:
        """Copy the current auth snapshot into immutable local values."""
        get = self._config.get
        users = get("auth.users", {})
        if not isinstance(users, dict):
            users = {}
        copied_users: dict[str, tuple[bytes, bytes] | None] = {}
        for username, record in users.items():
            if not isinstance(username, str) or not isinstance(record, dict):
                continue
            try:
                salt = bytes.fromhex(record.get("salt", ""))
                stored_hash = bytes.fromhex(record.get("hash", ""))
            except (TypeError, ValueError):
                copied_users[username] = None
                continue
            if not salt or not stored_hash:
                copied_users[username] = None
            else:
                copied_users[username] = (salt, stored_hash)

        settings = (
            bool(get("auth.enabled", False)),
            str(get("auth.realm", "proxy")),
            copied_users,
            max(1, _as_nonnegative_int(get("auth.max_failures", 5), 5)),
            _as_nonnegative_int(get("auth.lockout_seconds", 60), 60),
            _as_nonnegative_int(
                get("auth.failure_window_seconds", 300), 300
            ),
        )
        with self._settings_lock:
            self._enabled, self._realm, self._users, self._max_failures, \
                self._lockout_seconds, self._failure_window = settings

    def _on_config_reload(self, *_args: Any) -> None:
        self._load_settings()
        with self._cache_lock:
            self._cache.clear()

    def check(self, headers: dict, client_ip: str) -> AuthResult:
        """Validate one proxy request's credentials without exposing secrets."""
        with self._settings_lock:
            enabled = self._enabled
        if not enabled:
            # Development mode must not parse credentials or mutate lockout state.
            return AuthResult(ok=True)

        now = self._clock()
        locked, retry_after = self._lock_status(client_ip, now)
        if locked:
            result = AuthResult(
                ok=False,
                user=None,
                locked=True,
                retry_after=retry_after,
                reason="locked",
            )
            self._record_history(client_ip, None, "locked", now)
            return result

        if not isinstance(headers, dict):
            return self._failed(client_ip, None, "malformed", now)
        value = headers.get("proxy-authorization")
        if value is None:
            return self._failed(client_ip, None, "missing", now)
        parsed = self._parse_basic_header(value)
        if parsed is None:
            return self._failed(client_ip, None, "malformed", now)
        username, password = parsed

        # Store only a digest of the raw header; the header itself is sensitive.
        cache_key = hashlib.sha256(value.encode("utf-8")).digest()
        cached_user = self._cached_user(cache_key, now)
        if cached_user is not None:
            self._clear_failures(client_ip)
            return AuthResult(ok=True, user=cached_user)

        valid = self._verify(username, password)
        if valid:
            self._clear_failures(client_ip)
            self._cache_success(cache_key, username, now)
            return AuthResult(ok=True, user=username)
        return self._failed(client_ip, username, "bad_creds", now)

    def challenge_response(self) -> bytes:
        """Return a complete HTTP 407 response."""
        with self._settings_lock:
            realm = self._realm.replace("\r", "").replace("\n", "")
            realm = realm.replace("\\", "\\\\").replace('"', '\\"')
        # Header values are sanitized before bytes are assembled into the response.
        body = b""
        header_realm = realm.encode("utf-8", errors="replace")
        return (
            b"HTTP/1.1 407 Proxy Authentication Required\r\n"
            + b"Proxy-Authenticate: Basic realm=\""
            + header_realm
            + b"\"\r\nContent-Length: 0\r\n"
            + b"Connection: close\r\n\r\n"
            + body
        )

    def locked_response(self, retry_after: int) -> bytes:
        """Return a complete HTTP 429 response with a safe retry interval."""
        if isinstance(retry_after, bool):
            seconds = 0
        else:
            try:
                seconds = max(0, int(retry_after))
            except (TypeError, ValueError, OverflowError):
                seconds = 0
        body = b""
        return (
            b"HTTP/1.1 429 Too Many Requests\r\n"
            + f"Retry-After: {seconds}\r\n".encode("ascii")
            + b"Content-Length: 0\r\nConnection: close\r\n\r\n"
            + body
        )

    def recent_failures(self, limit: int = 50) -> list:
        """Return a safe, newest-last copy of recent authentication failures."""
        try:
            requested = int(limit)
        except (TypeError, ValueError, OverflowError):
            requested = 0
        if requested <= 0:
            return []
        requested = min(requested, _MAX_FAILURE_HISTORY)
        with self._state_lock:
            records = list(self._history)[-requested:]
            return [dict(record) for record in records]

    def _parse_basic_header(self, value: Any) -> Optional[tuple[str, bytes]]:
        # Strict decoding rejects malformed or padded credentials instead of repairing them.
        if not isinstance(value, str) or len(value) > _MAX_HEADER_LENGTH:
            return None
        parts = value.split(None, 1)
        if len(parts) != 2 or parts[0].lower() != "basic":
            return None
        try:
            decoded = base64.b64decode(parts[1], validate=True)
            credentials = decoded.decode("utf-8", errors="strict")
        except (ValueError, UnicodeError, binascii.Error):
            return None
        if ":" not in credentials:
            return None
        username, password = credentials.split(":", 1)
        return username, password.encode("utf-8")

    def _verify(self, username: str, password: bytes) -> bool:
        with self._settings_lock:
            record = self._users.get(username)
        if record is None:
            # Unknown users still perform scrypt so username lookup is less observable.
            salt = _DUMMY_SALT
            expected = self._dummy_digest
        else:
            salt, expected = record
        try:
            derived = self._derive(password, salt)
        except (ValueError, TypeError):
            derived = self._derive(password, _DUMMY_SALT)
            expected = self._dummy_digest
        matches = hmac.compare_digest(derived, expected)
        return record is not None and matches

    @staticmethod
    def _derive(password: bytes, salt: bytes = _DUMMY_SALT) -> bytes:
        return hash_password(password, salt)

    def _cached_user(self, key: bytes, now: float) -> Optional[str]:
        with self._cache_lock:
            entry = self._cache.get(key)
            if entry is None:
                return None
            username, expiry = entry
            if expiry <= now:
                del self._cache[key]
                return None
            self._cache.move_to_end(key)
            return username

    def _cache_success(self, key: bytes, username: str, now: float) -> None:
        with self._cache_lock:
            # The cache contains successful usernames and expiry times only.
            expired = [
                cached_key
                for cached_key, (_, expiry) in self._cache.items()
                if expiry <= now
            ]
            for cached_key in expired:
                del self._cache[cached_key]
            self._cache[key] = (username, now + _CACHE_TTL)
            self._cache.move_to_end(key)
            while len(self._cache) > _MAX_CACHE_ENTRIES:
                self._cache.popitem(last=False)

    def _lock_status(self, client_ip: str, now: float) -> tuple[bool, int]:
        with self._settings_lock:
            window = self._failure_window
        with self._state_lock:
            entry = self._failures.get(client_ip)
            if entry is None:
                return False, 0
            timestamps, locked_until = entry
            if locked_until > now:
                return True, max(1, math.ceil(locked_until - now))
            self._prune_timestamps(timestamps, now, window)
            if not timestamps and locked_until <= now:
                del self._failures[client_ip]
            return False, 0

    def _failed(
        self,
        client_ip: str,
        username: Optional[str],
        reason: str,
        now: Optional[float] = None,
    ) -> AuthResult:
        current = self._clock() if now is None else now
        self._record_history(client_ip, username, reason, current)
        if reason != "bad_creds":
            return AuthResult(ok=False, user=username, reason=reason)
        with self._settings_lock:
            threshold = self._max_failures
            window = self._failure_window
            duration = self._lockout_seconds
        with self._state_lock:
            # Ordered storage bounds the number of client identities retained.
            self._evict_failure_clients(client_ip)
            timestamps, _ = self._failures.get(
                client_ip, (deque(), 0.0)
            )
            self._prune_timestamps(timestamps, current, window)
            timestamps.append(current)
            locked_until = 0.0
            if len(timestamps) >= threshold:
                locked_until = current + duration
                timestamps.clear()
            self._failures[client_ip] = (timestamps, locked_until)
            self._failures.move_to_end(client_ip)
        return AuthResult(ok=False, user=username, reason="bad_creds")

    def _clear_failures(self, client_ip: str) -> None:
        with self._state_lock:
            self._failures.pop(client_ip, None)

    def _record_history(
        self,
        client_ip: str,
        username: Optional[str],
        reason: str,
        now: float,
    ) -> None:
        record = {
            "ts": datetime.now(timezone.utc).isoformat(
                timespec="milliseconds"
            ).replace("+00:00", "Z"),
            "client_ip": client_ip,
            "user": username,
            "reason": reason,
        }
        with self._state_lock:
            self._history.append(record)

    def _evict_failure_clients(self, current_ip: str) -> None:
        if current_ip not in self._failures:
            while len(self._failures) >= _MAX_TRACKED_CLIENTS:
                self._failures.popitem(last=False)

    @staticmethod
    def _prune_timestamps(
        timestamps: deque[float], now: float, window: float = 300.0
    ) -> None:
        cutoff = now - max(0.0, window)
        while timestamps and timestamps[0] < cutoff:
            timestamps.popleft()


def _as_nonnegative_int(value: Any, default: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        return default
    return max(0, value)


def build_auth(config: Any) -> Authenticator:
    """Build an authenticator from the shared configuration object."""
    return Authenticator(config)