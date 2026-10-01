"""
proxy.control.responses
~~~~~~~~~~~~~~~~~~~~~~~
Pure HTTP response builders for the rules and security control layer.

Constructs complete HTTP/1.1 responses for:
- filtered requests (403 Forbidden)
- missing or invalid proxy authentication (407 Proxy Authentication Required)
- authentication lockout (429 Too Many Requests)

This module uses no sockets, networking, request parsing, authentication,
filtering, configuration state, or logging. It only converts safe inputs into
response bytes for the caller to send.

Public API
----------
- ``build_forbidden`` - compatibility helper used by ``filter_engine``
- ``build_forbidden_response`` - descriptive 403 response builder
- ``build_proxy_auth_required_response`` - 407 response builder
- ``build_too_many_requests_response`` - 429 response builder
"""
from __future__ import annotations

from html import escape
from typing import Mapping

from proxy.interfaces import Decision


# ── response construction ─────────────────────────────────────

def _build_response(
    status_line: str,
    headers: Mapping[str, str],
    body: bytes,
) -> bytes:
    """Build a complete response with byte-accurate framing."""
    _validate_header_text(status_line, "status line")
    header_lines = [status_line]
    for name, value in headers.items():
        _validate_header_text(name, "header name")
        _validate_header_text(value, "header value")
        header_lines.append(f"{name}: {value}")
    header_lines.append(f"Content-Length: {len(body)}")
    header_lines.append("Connection: close")
    return ("\r\n".join(header_lines) + "\r\n\r\n").encode("utf-8") + body


def _validate_header_text(value: object, label: str) -> None:
    """Reject non-text header data and CR/LF response-splitting characters."""
    if not isinstance(value, str):
        raise TypeError(f"{label} must be a string")
    if "\r" in value or "\n" in value:
        raise ValueError(f"{label} must not contain CR or LF")


def _safe_realm(realm: str) -> str:
    """Return a realm safe for a quoted HTTP header value."""
    if not isinstance(realm, str):
        raise TypeError("realm must be a string")
    if any(ord(char) < 32 or ord(char) == 0x7F for char in realm):
        raise ValueError("realm must not contain control characters")
    return realm.replace("\\", "\\\\").replace('"', '\\"')


# def _safe_retry_after(retry_after: int) -> int:
#     """Normalize a retry interval into a non-negative integer."""
#     if isinstance(retry_after, bool) or not isinstance(retry_after, int):
#         raise TypeError("retry_after must be an integer")
#     return max(0, retry_after)

def _safe_retry_after(retry_after: int) -> int:
    """Validate a retry interval as a non-negative integer."""
    if isinstance(retry_after, bool) or not isinstance(retry_after, int):
        raise TypeError("retry_after must be an integer")
    if retry_after < 0:
        raise ValueError("retry_after must be non-negative")
    return retry_after


# ── security response builders ─────────────────────────────────

def build_forbidden_response(decision: Decision) -> bytes:
    """Build a complete HTTP/1.1 403 response for a blocked request.

    Only the human-readable decision reason is included. The internal rule
    identifier is deliberately excluded from the response body.
    """
    reason = escape(str(decision.reason or "Forbidden"), quote=True)
    body_text = (
        "<!doctype html>\n"
        "<html><head><title>403 Forbidden</title></head>"
        "<body><h1>403 Forbidden</h1>"
        f"<p>Request blocked: {reason}</p>"
        "</body></html>\n"
    )
    body = body_text.encode("utf-8")
    return _build_response(
        "HTTP/1.1 403 Forbidden",
        {"Content-Type": "text/html; charset=utf-8"},
        body,
    )


def build_forbidden(decision: Decision) -> bytes:
    """Build a 403 response using the filter engine's existing import name."""
    return build_forbidden_response(decision)


def build_proxy_auth_required_response(realm: str = "proxy") -> bytes:
    """Build a complete HTTP/1.1 407 authentication challenge response."""
    safe_realm = _safe_realm(realm)
    return _build_response(
        "HTTP/1.1 407 Proxy Authentication Required",
        {"Proxy-Authenticate": f'Basic realm="{safe_realm}"'},
        b"",
    )


def build_too_many_requests_response(retry_after: int) -> bytes:
    """Build a complete HTTP/1.1 429 lockout response."""
    seconds = _safe_retry_after(retry_after)
    return _build_response(
        "HTTP/1.1 429 Too Many Requests",
        {"Retry-After": str(seconds)},
        b"",
    )


__all__ = [
    "build_forbidden",
    "build_forbidden_response",
    "build_proxy_auth_required_response",
    "build_too_many_requests_response",
]
