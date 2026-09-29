"""
proxy.control.config
~~~~~~~~~~~~~~~~~~~~
Configuration subsystem for the proxy server.

Implements the ``Config`` protocol from ``proxy.interfaces``:
load, validate, merge, reload, and redact configuration from
multiple sources with immutable-snapshot semantics.

Public API
----------
- ``ConfigError``      – raised when configuration is invalid.
- ``Config``           – thread-safe configuration manager.
- ``load_config``      – build a ``Config`` from all sources.
- ``install_sighup``   – attach a SIGHUP reload handler.
"""
from __future__ import annotations

import argparse
import copy
import json
import logging
import os
import signal
import sys
import threading
from pathlib import Path
from typing import (
    Any,
    Callable,
    Dict,
    List,
    Optional,
    Sequence,
    Tuple,
)

__all__ = ["ConfigError", "Config", "load_config", "install_sighup"]

_log = logging.getLogger(__name__)

# ── sensitive-key detection ────────────────────────────────────
_EXACT_REDACT_KEYS = frozenset({"salt", "hash"})
_SUBSTRING_REDACT_KEYS = ("password", "secret", "token")
_REDACTED = "[REDACTED]"


def _is_sensitive_key(key: str) -> bool:
    """Return True if *key* names a secret that must be redacted."""
    low = key.lower()
    if low in _EXACT_REDACT_KEYS:
        return True
    return any(sub in low for sub in _SUBSTRING_REDACT_KEYS)


# ── deep helpers ───────────────────────────────────────────────
def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """Return a new dict with *override* deep-merged onto *base*.

    Dictionary values are merged recursively; all other types in
    *override* replace the corresponding value in *base*.  Neither
    input is mutated.
    """
    merged: Dict[str, Any] = {}
    all_keys = set(base) | set(override)
    for key in all_keys:
        if key in override and key in base:
            bval = base[key]
            oval = override[key]
            if isinstance(bval, dict) and isinstance(oval, dict):
                merged[key] = _deep_merge(bval, oval)
            else:
                merged[key] = copy.deepcopy(oval)
        elif key in override:
            merged[key] = copy.deepcopy(override[key])
        else:
            merged[key] = copy.deepcopy(base[key])
    return merged


def _deep_redact(obj: Any) -> Any:
    """Return a deep copy of *obj* with sensitive values replaced."""
    if isinstance(obj, dict):
        out: Dict[str, Any] = {}
        for k, v in obj.items():
            if _is_sensitive_key(k):
                out[k] = _REDACTED
            else:
                out[k] = _deep_redact(v)
        return out
    if isinstance(obj, list):
        return [_deep_redact(item) for item in obj]
    return copy.deepcopy(obj)


def _set_dotted(target: Dict[str, Any], dotted_key: str,
                value: Any) -> None:
    """Set a value in *target* using a ``"a.b.c"`` dotted path."""
    parts = dotted_key.split(".")
    cur = target
    for part in parts[:-1]:
        if part not in cur or not isinstance(cur[part], dict):
            cur[part] = {}
        cur = cur[part]
    cur[parts[-1]] = value


def _get_dotted(data: Dict[str, Any], dotted_key: str,
                default: Any = None) -> Any:
    """Retrieve a value from *data* using a ``"a.b.c"`` dotted path."""
    cur: Any = data
    for part in dotted_key.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return default
        cur = cur[part]
    return cur


def _collect_all_dotted_keys(
    data: Dict[str, Any], prefix: str = "",
) -> List[str]:
    """Return every leaf dotted-key in *data*."""
    keys: List[str] = []
    for k, v in data.items():
        full = f"{prefix}{k}" if not prefix else f"{prefix}.{k}"
        if isinstance(v, dict):
            keys.extend(_collect_all_dotted_keys(v, full))
        else:
            keys.append(full)
    return keys


# ── safe error message helpers ─────────────────────────────────
def _safe_value_repr(key: str, value: Any) -> str:
    """Return a representation of *value* safe for diagnostics.

    If the key is sensitive the value is replaced with ``[REDACTED]``.
    """
    if _is_sensitive_key(key):
        return _REDACTED
    return repr(value)


# ── exception ──────────────────────────────────────────────────
class ConfigError(Exception):
    """Raised when configuration loading or validation fails."""


# ── defaults (A6.5) ───────────────────────────────────────────
_DEFAULTS: Dict[str, Any] = {
    "proxy": {
        "host": "127.0.0.1",
        "port": 8080,
        "max_threads": 100,
        "backlog": 128,
        "connect_timeout": 10.0,
        "read_timeout": 30.0,
        "idle_timeout": 60.0,
        "max_header_bytes": 16384,
    },
    "admin": {
        "host": "127.0.0.1",
        "port": 8081,
    },
    "filter": {
        "mode": "denylist",
        "deny_domains": [],
        "allow_domains": [],
        "blocked_ports": [25],
        "allowed_ports": [],
        "deny_url_regex": [],
        "block_private_ips": True,
        "private_allow": [],
    },
    "auth": {
        "enabled": False,
        "realm": "proxy",
        "users": {},
        "max_failures": 5,
        "lockout_seconds": 60,
        "failure_window_seconds": 300,
    },
    "logging": {
        "file": "logs/proxy.jsonl",
        "max_bytes": 5_000_000,
        "backups": 3,
        "console": True,
        "level": "INFO",
        "ring_size": 2000,
        "log_query": False,
    },
}

# All known dotted keys (computed once at module load).
_KNOWN_KEYS: frozenset[str] = frozenset(
    _collect_all_dotted_keys(_DEFAULTS)
)


# ── validation ─────────────────────────────────────────────────
def _validate(data: Dict[str, Any]) -> Tuple[List[str], List[str]]:
    """Validate *data* against the A6.5 schema.

    Returns ``(errors, warnings)`` where *errors* lists every
    validation failure (one per problem) and *warnings* lists
    unknown-key notices.
    """
    errors: List[str] = []
    warnings: List[str] = []

    # --- unknown keys ---
    user_keys = set(_collect_all_dotted_keys(data))
    # Also collect intermediate dict keys so "proxy" itself isn't
    # flagged when "proxy.port" etc. exist.
    known_prefixes = {k.rsplit(".", 1)[0] for k in _KNOWN_KEYS if "." in k}
    for uk in sorted(user_keys - _KNOWN_KEYS):
        # Don't warn about sub-keys of auth.users since those are
        # user-defined credential entries (each is a dict of
        # {salt, hash}).
        if uk.startswith("auth.users."):
            continue
        warnings.append(f"Unknown configuration key: {uk}")

    def _check_type(key: str, expected: type, label: str) -> Any:
        val = _get_dotted(data, key)
        if val is None:
            return val  # missing → will use default
        if not isinstance(val, expected):
            errors.append(
                f"{key} must be {label}, got "
                f"{_safe_value_repr(key, val)}"
            )
            return None
        return val

    def _check_int(key: str, *, min_val: Optional[int] = None,
                   max_val: Optional[int] = None) -> None:
        val = _get_dotted(data, key)
        if val is None:
            return
        if not isinstance(val, int) or isinstance(val, bool):
            errors.append(
                f"{key} must be an integer, got "
                f"{_safe_value_repr(key, val)}"
            )
            return
        if min_val is not None and val < min_val:
            errors.append(f"{key} must be >= {min_val}, got {val}")
        if max_val is not None and val > max_val:
            errors.append(f"{key} must be <= {max_val}, got {val}")

    def _check_number(key: str, *, min_val: Optional[float] = None,
                      max_val: Optional[float] = None) -> None:
        val = _get_dotted(data, key)
        if val is None:
            return
        if not isinstance(val, (int, float)) or isinstance(val, bool):
            errors.append(
                f"{key} must be a number, got "
                f"{_safe_value_repr(key, val)}"
            )
            return
        if min_val is not None and val < min_val:
            errors.append(f"{key} must be >= {min_val}, got {val}")
        if max_val is not None and val > max_val:
            errors.append(f"{key} must be <= {max_val}, got {val}")

    def _check_bool(key: str) -> None:
        val = _get_dotted(data, key)
        if val is None:
            return
        if not isinstance(val, bool):
            errors.append(
                f"{key} must be a boolean, got "
                f"{_safe_value_repr(key, val)}"
            )

    def _check_str(key: str, *, choices: Optional[Sequence[str]] = None
                   ) -> None:
        val = _get_dotted(data, key)
        if val is None:
            return
        if not isinstance(val, str):
            errors.append(
                f"{key} must be a string, got "
                f"{_safe_value_repr(key, val)}"
            )
            return
        if choices and val not in choices:
            errors.append(
                f"{key} must be one of {list(choices)}, got "
                f"{_safe_value_repr(key, val)}"
            )

    def _check_list(key: str, item_type: Optional[type] = None,
                    item_label: str = "") -> None:
        val = _get_dotted(data, key)
        if val is None:
            return
        if not isinstance(val, list):
            errors.append(
                f"{key} must be a list, got "
                f"{_safe_value_repr(key, val)}"
            )
            return
        if item_type is not None:
            for i, item in enumerate(val):
                if not isinstance(item, item_type):
                    errors.append(
                        f"{key}[{i}] must be {item_label}, got "
                        f"{_safe_value_repr(key, item)}"
                    )

    # --- proxy section ---
    _check_str("proxy.host")
    _check_int("proxy.port", min_val=1, max_val=65535)
    _check_int("proxy.max_threads", min_val=1)
    _check_int("proxy.backlog", min_val=1)
    _check_number("proxy.connect_timeout", min_val=0)
    _check_number("proxy.read_timeout", min_val=0)
    _check_number("proxy.idle_timeout", min_val=0)
    _check_int("proxy.max_header_bytes", min_val=1)

    # --- admin section ---
    _check_str("admin.host")
    _check_int("admin.port", min_val=0, max_val=65535)

    # --- filter section ---
    _check_str("filter.mode", choices=("denylist", "allowlist"))
    _check_list("filter.deny_domains", str, "a string")
    _check_list("filter.allow_domains", str, "a string")
    _check_list("filter.blocked_ports", int, "an integer")
    _check_list("filter.allowed_ports", int, "an integer")
    _check_list("filter.deny_url_regex", str, "a string")
    _check_bool("filter.block_private_ips")
    _check_list("filter.private_allow", str, "a string")

    # Validate port values inside port lists.
    for list_key in ("filter.blocked_ports", "filter.allowed_ports"):
        val = _get_dotted(data, list_key)
        if isinstance(val, list):
            for i, item in enumerate(val):
                if isinstance(item, int) and not isinstance(item, bool):
                    if item < 1 or item > 65535:
                        errors.append(
                            f"{list_key}[{i}] must be 1-65535, "
                            f"got {item}"
                        )

    # --- auth section ---
    _check_bool("auth.enabled")
    _check_str("auth.realm")
    auth_users = _get_dotted(data, "auth.users")
    if auth_users is not None:
        if not isinstance(auth_users, dict):
            errors.append(
                "auth.users must be a dict, got "
                f"{type(auth_users).__name__}"
            )
        else:
            for uname, udata in auth_users.items():
                if not isinstance(udata, dict):
                    errors.append(
                        f"auth.users.{uname} must be a dict"
                    )
                    continue
                if "salt" not in udata:
                    errors.append(
                        f"auth.users.{uname} is missing 'salt'"
                    )
                if "hash" not in udata:
                    errors.append(
                        f"auth.users.{uname} is missing 'hash'"
                    )
                # Do NOT include salt/hash values in messages.

    _check_int("auth.max_failures", min_val=1)
    _check_int("auth.lockout_seconds", min_val=0)
    _check_int("auth.failure_window_seconds", min_val=0)

    # --- logging section ---
    _check_str("logging.file")
    _check_int("logging.max_bytes", min_val=1)
    _check_int("logging.backups", min_val=0)
    _check_bool("logging.console")
    _check_str("logging.level",
               choices=("DEBUG", "INFO", "WARNING", "ERROR"))
    _check_int("logging.ring_size", min_val=1)
    _check_bool("logging.log_query")

    return errors, warnings


# ── JSON file loading ──────────────────────────────────────────
def _load_json_file(path: str) -> Dict[str, Any]:
    """Load and return a JSON object from *path*.

    Raises ``ConfigError`` on any I/O or parsing failure with a safe
    message that never includes file content.
    """
    p = Path(path)
    if not p.exists():
        raise ConfigError(f"Configuration file not found: {path}")
    if p.is_dir():
        raise ConfigError(
            f"Configuration path is a directory, not a file: {path}"
        )
    try:
        text = p.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(
            f"Cannot read configuration file {path}: {exc}"
        ) from exc
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ConfigError(
            f"Invalid JSON in configuration file {path}: {exc}"
        ) from exc
    if not isinstance(data, dict):
        raise ConfigError(
            f"Configuration file {path} must contain a JSON object "
            f"(got {type(data).__name__})"
        )
    return data


# ── CLI argument parsing ───────────────────────────────────────
def _build_parser() -> argparse.ArgumentParser:
    """Build the argument parser for proxy CLI flags."""
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--config", type=str, default=None,
                        help="Path to JSON config file")
    parser.add_argument("--port", type=int, default=None)
    parser.add_argument("--host", type=str, default=None)
    parser.add_argument("--admin-port", type=int, default=None)
    parser.add_argument("--log-file", type=str, default=None)
    parser.add_argument(
        "--set", dest="overrides", action="append", default=[],
        metavar="key=value",
        help="Dot-separated config override, e.g. "
             "--set security.auth.enabled=true",
    )
    return parser


def _parse_set_value(raw: str) -> Any:
    """Parse a ``--set key=value`` value as JSON, falling back to str."""
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return raw


def _cli_overrides_to_dict(
    args: argparse.Namespace,
) -> Tuple[Dict[str, Any], List[str]]:
    """Convert parsed CLI arguments into a configuration overlay dict.

    Returns ``(overlay, errors)``  where *errors* collects malformed
    ``--set`` entries rather than raising immediately, so that all CLI
    problems can be reported at once.
    """
    overlay: Dict[str, Any] = {}
    errors: List[str] = []

    # Named flags map to known dotted keys.
    if args.host is not None:
        _set_dotted(overlay, "proxy.host", args.host)
    if args.port is not None:
        _set_dotted(overlay, "proxy.port", args.port)
    if getattr(args, "admin_port", None) is not None:
        _set_dotted(overlay, "admin.port", args.admin_port)
    if getattr(args, "log_file", None) is not None:
        _set_dotted(overlay, "logging.file", args.log_file)

    # Generic --set overrides.
    for entry in args.overrides:
        eq_idx = entry.find("=")
        if eq_idx < 0:
            errors.append(
                f"Malformed --set (missing '='): {entry}"
            )
            continue
        key = entry[:eq_idx].strip()
        raw_val = entry[eq_idx + 1:]
        if not key:
            errors.append(f"Malformed --set (empty key): {entry}")
            continue
        if not all(
            part.isidentifier() for part in key.split(".")
        ):
            errors.append(
                f"Malformed --set (invalid dotted key): {key}"
            )
            continue
        value = _parse_set_value(raw_val)
        _set_dotted(overlay, key, value)

    return overlay, errors


# ── Config class ───────────────────────────────────────────────
class Config:
    """Thread-safe immutable-snapshot configuration manager.

    Satisfies the ``proxy.interfaces.Config`` protocol.

    Read path (``get``) is lock-free — it reads a single object
    reference that is atomically replaced on ``reload``.

    Write path (``reload``) acquires ``_reload_lock`` to ensure
    only one rebuild runs at a time.
    """

    def __init__(
        self,
        snapshot: Dict[str, Any],
        *,
        config_path: Optional[str] = None,
        argv: Optional[List[str]] = None,
    ) -> None:
        # The single source of truth for readers.  Replaced
        # atomically (reference swap) on successful reload.
        self._snapshot: Dict[str, Any] = snapshot

        # Sources remembered for reload.
        self._config_path: Optional[str] = config_path
        self._argv: Optional[List[str]] = argv

        # Reload serialisation.
        self._reload_lock = threading.Lock()

        # Protocol-required attribute.
        self.last_error: Optional[str] = None

        # Reload listeners — callables invoked after a successful
        # snapshot swap so that dependent components (filter engine,
        # auth) can rebuild compiled state.
        self._listeners: List[Callable[[Config], None]] = []
        self._listeners_lock = threading.Lock()

    # ── public API (Config protocol) ──────────────────────────

    def get(self, key: str, default: Any = None) -> Any:
        """Return a configuration value using a dotted key.

        Lock-free: reads the current snapshot reference.
        """
        return _get_dotted(self._snapshot, key, default)

    def reload(self) -> bool:
        """Rebuild configuration from all sources.

        On success the snapshot is atomically replaced, listeners
        are notified, ``last_error`` is cleared, and ``True`` is
        returned.

        On failure the previous snapshot is preserved,
        ``last_error`` is set to a safe message, and ``False`` is
        returned.
        """
        with self._reload_lock:
            try:
                new_snapshot = _build_snapshot(
                    config_path=self._config_path,
                    argv=self._argv,
                )
                # Atomic reference swap.
                self._snapshot = new_snapshot
                self.last_error = None
            except ConfigError as exc:
                self.last_error = str(exc)
                return False
            except Exception as exc:
                self.last_error = (
                    f"Unexpected error during reload: "
                    f"{type(exc).__name__}"
                )
                return False

        # Notify listeners outside the reload lock so a slow
        # listener cannot block the next reload attempt.
        self._notify_listeners()
        return True

    def as_dict(self, redact: bool = True) -> Dict[str, Any]:
        """Return a deep copy of the current configuration.

        When *redact* is True, sensitive keys are replaced with
        ``"[REDACTED]"``.  The returned dict is always a fresh deep
        copy — callers cannot mutate internal state.
        """
        snap = self._snapshot  # single atomic read
        if redact:
            return _deep_redact(snap)
        return copy.deepcopy(snap)

    # ── listener management ───────────────────────────────────

    def add_reload_listener(
        self, listener: Callable[["Config"], None],
    ) -> None:
        """Register a callable to be invoked after a successful reload."""
        with self._listeners_lock:
            self._listeners.append(listener)

    def remove_reload_listener(
        self, listener: Callable[["Config"], None],
    ) -> None:
        """Unregister a previously added reload listener."""
        with self._listeners_lock:
            try:
                self._listeners.remove(listener)
            except ValueError:
                pass

    def _notify_listeners(self) -> None:
        """Call each registered listener, catching exceptions."""
        with self._listeners_lock:
            listeners = list(self._listeners)
        for fn in listeners:
            try:
                fn(self)
            except Exception:
                _log.exception("Reload listener %r raised", fn)


# ── snapshot builder (stateless) ───────────────────────────────
def _build_snapshot(
    *,
    config_path: Optional[str] = None,
    argv: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Build and validate a configuration snapshot.

    This is a pure function (aside from file/env I/O): it merges
    all sources, validates, and returns the frozen snapshot dict.
    Raises ``ConfigError`` on any validation failure.
    """
    all_errors: List[str] = []

    # 1. Start with defaults.
    merged = copy.deepcopy(_DEFAULTS)

    # 2. JSON config file (from --config or method argument).
    # Determine config path: explicit arg > argv parse > None.
    cli_config_path = config_path

    # We need CLI args for both the --config flag and later
    # overrides, so parse them early.
    parser = _build_parser()
    if argv is not None:
        try:
            args, _ = parser.parse_known_args(argv)
        except SystemExit:
            args = argparse.Namespace(
                config=None, host=None, port=None,
                admin_port=None, log_file=None, overrides=[],
            )
    else:
        args = argparse.Namespace(
            config=None, host=None, port=None,
            admin_port=None, log_file=None, overrides=[],
        )

    # --config from CLI overrides the programmatic config_path.
    if args.config is not None:
        cli_config_path = args.config

    # Load the JSON file if one was specified.
    if cli_config_path is not None:
        file_data = _load_json_file(cli_config_path)
        merged = _deep_merge(merged, file_data)

    # 3. PROXY_CONFIG environment variable (path to another JSON).
    env_path = os.environ.get("PROXY_CONFIG")
    if env_path:
        env_data = _load_json_file(env_path)
        merged = _deep_merge(merged, env_data)

    # 4. CLI overrides.
    cli_overlay, cli_errors = _cli_overrides_to_dict(args)
    all_errors.extend(cli_errors)
    if cli_overlay:
        merged = _deep_merge(merged, cli_overlay)

    # 5. Validate.
    val_errors, val_warnings = _validate(merged)
    all_errors.extend(val_errors)

    for w in val_warnings:
        _log.warning(w)

    if all_errors:
        raise ConfigError("\n".join(all_errors))

    return merged


# ── public factory ─────────────────────────────────────────────
def load_config(argv: Optional[List[str]] = None) -> Config:
    """Load, merge, validate, and return a ``Config`` object.

    Parameters
    ----------
    argv:
        Command-line arguments to parse.  Defaults to
        ``sys.argv[1:]`` when ``None``.

    Raises
    ------
    ConfigError
        When the merged configuration fails validation.  The
        exception message lists **all** problems, one per line,
        with no secret values.
    """
    if argv is None:
        argv = sys.argv[1:]

    # We parse argv once here to extract --config, then pass the
    # raw argv to _build_snapshot so reload can re-parse.
    parser = _build_parser()
    try:
        pre_args, _ = parser.parse_known_args(argv)
    except SystemExit:
        pre_args = argparse.Namespace(config=None)

    config_path = pre_args.config

    snapshot = _build_snapshot(config_path=config_path, argv=argv)

    return Config(
        snapshot,
        config_path=config_path,
        argv=argv,
    )


# ── SIGHUP handler ─────────────────────────────────────────────
def install_sighup(config: Config) -> bool:
    """Install a SIGHUP handler that triggers ``config.reload()``.

    Returns ``True`` when SIGHUP is available and the handler was
    installed.  Returns ``False`` on platforms without SIGHUP
    (e.g. Windows) without raising.
    """
    if not hasattr(signal, "SIGHUP"):
        return False

    def _handler(signum: int, frame: Any) -> None:
        config.reload()

    signal.signal(signal.SIGHUP, _handler)  # type: ignore[attr-defined]
    return True
