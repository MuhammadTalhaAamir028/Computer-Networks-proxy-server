"""proxy/interfaces.py -- FROZEN CONTRACT. Change only by PR approved by all three."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Optional, Protocol

EVENT_KINDS = ("conn_open", "conn_close", "req_forward", "req_blocked",
               "auth_fail", "tunnel_open", "tunnel_close", "error")
STAT_KEYS = ("requests_total", "requests_blocked", "active_conns",
             "bytes_up", "bytes_down", "errors")

@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str = ""              # human-readable, safe to show the client
    rule: Optional[str] = None    # machine id, e.g. "deny:domain:*.ads.com"

@dataclass(frozen=True)
class AuthResult:
    ok: bool
    user: Optional[str] = None
    locked: bool = False          # True when the client IP is in lockout
    retry_after: int = 0          # seconds, valid when locked
    reason: str = ""              # missing | malformed | bad_creds | locked | ""

class FilterEngine(Protocol):
    def check(self, host: str, port: int, path: Optional[str], method: str) -> Decision: ...
    def check_ip(self, ip: str, port: int) -> Decision: ...      # resolved address
    def describe(self) -> dict: ...                              # rules, for the UI
    def forbidden_response(self, decision: Decision) -> bytes: ...   # full 403 reply

class Auth(Protocol):
    def check(self, headers: dict, client_ip: str) -> AuthResult: ...  # keys lowercase
    def challenge_response(self) -> bytes: ...                   # full 407 reply
    def locked_response(self, retry_after: int) -> bytes: ...    # full 429 reply
    def recent_failures(self, limit: int = 50) -> list: ...      # redacted dicts

class Logger(Protocol):
    def event(self, kind: str, **fields: Any) -> None: ...       # never raises
    def tail(self, n: int = 100) -> list: ...                    # newest last

class Stats(Protocol):
    def inc(self, name: str, n: int = 1) -> None: ...            # n may be negative
    def snapshot(self) -> dict: ...

class Config(Protocol):
    last_error: Optional[str]
    def get(self, key: str, default: Any = None) -> Any: ...     # dotted: "proxy.port"
    def reload(self) -> bool: ...
    def as_dict(self, redact: bool = True) -> dict: ...