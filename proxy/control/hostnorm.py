"""
proxy.control.hostnorm
~~~~~~~~~~~~~~~~~~~~~~
Canonical hostname and IP normalization and parsing layer.

Provides deterministic, side-effect-free host validation, canonicalization,
and IP parsing for Member 2's Traffic Control & Security subsystem.
Consumed primarily by ``proxy.control.filter_engine``.

This module performs pure string normalization and standard IP parsing only.
It NEVER performs DNS resolution, opens network sockets, or applies security
filtering policies (such as SSRF or domain allow/deny rules).

Public API
----------
- ``HostNormError``      – Raised on empty, malformed, unsafe, or invalid host input.
- ``NormalizedHost``     – Immutable dataclass representing a canonicalized host or IP.
- ``IPAddress``          – Type alias for ``IPv4Address | IPv6Address``.
- ``normalize_host``     – Validate and canonicalize incoming request host/IP.
- ``normalize_hostname`` – Validate and canonicalize DNS hostnames (IDNA/lowercase).
- ``parse_ip_literal``   – Parse standard, legacy, or bracketed IP literals (no DNS).
"""
from __future__ import annotations

import encodings.idna
import ipaddress
import socket
import struct
import unicodedata
from dataclasses import dataclass
from typing import Optional, Union

__all__ = [
    "HostNormError",
    "IPAddress",
    "NormalizedHost",
    "normalize_host",
    "normalize_hostname",
    "parse_ip_literal",
]

IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]


class HostNormError(ValueError):
    """Raised when host normalization or validation fails.

    Inherits from ``ValueError`` so callers catching standard value errors
    handle normalization failures seamlessly.
    """


@dataclass(frozen=True)
class NormalizedHost:
    """Canonical representation of an incoming proxy host or IP literal.

    Attributes:
        value: The canonical normalized string (lowercase ASCII hostname or
            canonical IP address string).
        is_ip: True if the input represents an IP address literal, False if
            it represents a DNS hostname.
        ip: The parsed ``IPv4Address`` or ``IPv6Address`` object if ``is_ip``
            is True, otherwise ``None``.
    """

    value: str
    is_ip: bool
    ip: Optional[IPAddress] = None


def _validate_raw_host(host: str) -> None:
    """Perform baseline sanity checks on raw host input.

    Rejects:
    - Non-string types
    - Empty strings
    - Length exceeding 253 characters
    - Whitespace characters
    - NUL byte (\\x00)
    - ASCII or Unicode control characters
    """
    if not isinstance(host, str):
        raise HostNormError(f"Host must be a string, got {type(host).__name__}")
    if len(host) == 0:
        raise HostNormError("Host cannot be empty")
    if len(host) > 253:
        raise HostNormError(
            f"Host exceeds maximum length of 253 characters (got {len(host)})"
        )
    for c in host:
        if c == "\x00":
            raise HostNormError("Host contains NUL byte (\\x00)")
        if c.isspace():
            raise HostNormError("Host contains whitespace")
        if ord(c) < 32 or ord(c) == 127 or unicodedata.category(c) == "Cc":
            raise HostNormError(f"Host contains control character {c!r}")


def _looks_like_ipv4(host: str) -> bool:
    """Check whether a host string is formatted as an IPv4 address.

    Matches 1 to 4 dot-separated parts where each part is a decimal integer,
    octal representation (starting with '0'), or hexadecimal representation
    (starting with '0x' or '0X').
    """
    parts = host.split(".")
    if not (1 <= len(parts) <= 4):
        return False
    for p in parts:
        if not p:
            return False
        if p.startswith(("0x", "0X")):
            if len(p) <= 2 or not all(c in "0123456789abcdefABCDEF" for c in p[2:]):
                return False
        else:
            if not all(c in "0123456789" for c in p):
                return False
    return True


def _manual_parse_ipv4(host: str) -> Optional[int]:
    """Parse legacy BSD-style IPv4 representations manually.

    Handles 1 to 4 numeric parts formatted in decimal, octal, or hex:
    - 1 part (a): 32-bit integer
    - 2 parts (a.b): a is 8-bit net, b is 24-bit host
    - 3 parts (a.b.c): a and b are 8-bit, c is 16-bit host
    - 4 parts (a.b.c.d): each part is 8-bit

    This provides a reliable cross-platform fallback for Windows Winsock
    where ``socket.inet_aton`` fails on ``0xffffffff`` / ``4294967295`` due
    to the legacy ``INADDR_NONE`` (-1) return value collision.
    """
    parts = host.split(".")
    if not (1 <= len(parts) <= 4):
        return None
    nums = []
    for p in parts:
        try:
            if p.startswith(("0x", "0X")):
                nums.append(int(p, 16))
            elif p.startswith("0") and len(p) > 1:
                nums.append(int(p, 8))
            else:
                nums.append(int(p, 10))
        except ValueError:
            return None

    if len(nums) == 1:
        val = nums[0]
        return val if 0 <= val <= 0xFFFFFFFF else None
    if len(nums) == 2:
        a, b = nums
        return ((a << 24) | b) if (0 <= a <= 0xFF and 0 <= b <= 0xFFFFFF) else None
    if len(nums) == 3:
        a, b, c = nums
        return ((a << 24) | (b << 16) | c) if (
            0 <= a <= 0xFF and 0 <= b <= 0xFF and 0 <= c <= 0xFFFF
        ) else None
    if len(nums) == 4:
        a, b, c, d = nums
        return (
            ((a << 24) | (b << 16) | (c << 8) | d)
            if all(0 <= x <= 0xFF for x in nums)
            else None
        )
    return None


def _parse_ipv4_literal(host: str) -> ipaddress.IPv4Address:
    """Parse an IPv4 literal in standard dotted-decimal or legacy format.

    Uses ``ipaddress.IPv4Address`` for standard forms, ``socket.inet_aton``
    for legacy representations (hex, octal, short-form, decimal int), and
    a fallback for Windows Winsock INADDR_NONE edge cases.

    Raises:
        HostNormError: If the IPv4 representation is malformed or out-of-range.
    """
    # 1. Standard strict dotted-decimal (fast path)
    try:
        return ipaddress.IPv4Address(host)
    except ValueError:
        pass

    # 2. Legacy BSD forms using standard library socket.inet_aton
    try:
        packed = socket.inet_aton(host)
        ip_int = struct.unpack("!I", packed)[0]
        return ipaddress.IPv4Address(ip_int)
    except OSError:
        pass

    # 3. Fallback for Windows Winsock limitation on 0xffffffff / 4294967295
    val = _manual_parse_ipv4(host)
    if val is not None:
        return ipaddress.IPv4Address(val)

    raise HostNormError(f"Malformed or out-of-range IPv4 representation: {host!r}")


def normalize_hostname(host: str) -> str:
    """Validate and canonicalize a DNS hostname using lowercase and IDNA rules.

    Parameters:
        host: Raw or partially normalized hostname string.

    Returns:
        The canonical lowercase ASCII/Punycode domain name.

    Raises:
        HostNormError: If the hostname is empty, contains whitespace or
            control characters, has invalid bracket syntax, violates label
            length constraints, contains invalid characters, or fails IDNA
            conversion.
    """
    _validate_raw_host(host)

    if host.startswith("[") or host.endswith("]"):
        raise HostNormError("DNS hostname cannot contain square brackets")
    if "[" in host or "]" in host:
        raise HostNormError("Malformed hostname: misplaced square brackets")

    if host == ".":
        raise HostNormError("Host cannot be a single dot")
    if host.endswith("."):
        host = host[:-1]
        if host.endswith("."):
            raise HostNormError("Malformed hostname: multiple trailing dots")
    if host.startswith("."):
        raise HostNormError("Malformed hostname: leading dot")
    if ".." in host:
        raise HostNormError("Malformed hostname: empty domain label ('..')")

    host_lower = host.lower()

    # Standard library IDNA normalization (encodings.idna)
    try:
        if "xn--" in host_lower:
            # Validate that punycode decodes cleanly
            unicode_name = host_lower.encode("ascii").decode("idna")
            # And re-encodes to canonical ASCII
            ascii_host = unicode_name.encode("idna").decode("ascii").lower()
        else:
            ascii_host = host_lower.encode("idna").decode("ascii").lower()
    except (UnicodeError, IndexError) as exc:
        raise HostNormError(
            f"Invalid internationalized domain name (IDNA) {host!r}: {exc}"
        ) from exc

    # Enforce DNS label constraints (RFC 1123 / RFC 1035)
    labels = ascii_host.split(".")
    for label in labels:
        if not label:
            raise HostNormError("Malformed hostname: empty label")
        if len(label) > 63:
            raise HostNormError(
                f"Hostname label exceeds 63 characters (got {len(label)}): {label!r}"
            )
        if label.startswith("-") or label.endswith("-"):
            raise HostNormError(
                f"Hostname label cannot start or end with a hyphen: {label!r}"
            )
        for c in label:
            if not (c.isalnum() or c in "-_"):
                raise HostNormError(
                    f"Invalid character {c!r} in hostname {host!r}"
                )

    return ascii_host


def parse_ip_literal(host: str) -> Optional[IPAddress]:
    """Parse a host string as an IP address literal if applicable.

    Supports:
    - Standard IPv4 literals (e.g. ``127.0.0.1``)
    - Legacy IPv4 forms (decimal integer, hex, octal, short forms)
    - Standard IPv6 literals (e.g. ``::1``, ``2001:db8::1``)
    - Bracketed IPv6 literals (e.g. ``[::1]``, ``[2001:db8::1]``)
    - IPv4-mapped IPv6 literals (e.g. ``::ffff:127.0.0.1``, mapped to IPv4)

    Returns:
        The canonical ``IPv4Address`` or ``IPv6Address`` object if ``host``
        represents a valid IP literal, or ``None`` if it is not an IP literal
        or is malformed.

    This function NEVER performs DNS resolution.
    """
    if not isinstance(host, str) or not host:
        return None
    try:
        _validate_raw_host(host)
    except HostNormError:
        return None

    # Handle bracketed IPv6
    if host.startswith("["):
        if not host.endswith("]"):
            return None
        inner = host[1:-1]
        if not inner or "[" in inner or "]" in inner:
            return None
        try:
            ip = ipaddress.IPv6Address(inner)
            if ip.ipv4_mapped is not None:
                return ip.ipv4_mapped
            return ip
        except ValueError:
            return None

    if "[" in host or "]" in host:
        return None

    # Strip one trailing dot if present
    if host.endswith("."):
        host = host[:-1]

    # IPv6 literals without brackets
    if ":" in host:
        try:
            ip = ipaddress.IPv6Address(host)
            if ip.ipv4_mapped is not None:
                return ip.ipv4_mapped
            return ip
        except ValueError:
            return None

    # IPv4 and legacy IPv4 forms
    if _looks_like_ipv4(host):
        try:
            return _parse_ipv4_literal(host)
        except HostNormError:
            return None

    return None


def normalize_host(host: str) -> NormalizedHost:
    """Validate and canonicalize a proxy host string.

    Pipeline:
    1. Input validation: checks type, non-empty, max 253 chars, rejects whitespace,
       control characters, and NUL bytes.
    2. Bracket handling: strips square brackets for IPv6 literals. Rejects
       unbalanced or misplaced brackets.
    3. Trailing-dot handling: strips one trailing dot. Rejects multiple trailing
       dots or leading dots.
    4. IPv6 parsing: detects colon-separated literals, parses via ``ipaddress``,
       maps IPv4-mapped IPv6 (``::ffff:x.x.x.x``) to canonical ``IPv4Address``.
    5. IPv4 parsing: parses standard dotted-decimal and legacy formats (decimal,
       hex, octal, short forms) into canonical ``IPv4Address``.
    6. DNS hostname normalization: converts via standard ``encodings.idna``,
       lowercases, validates labels against RFC 1123 constraints.

    Returns:
        A ``NormalizedHost`` instance containing:
        - ``value``: Canonical lowercase string (hostname or IP string).
        - ``is_ip``: True if an IP literal was parsed, False if hostname.
        - ``ip``: The ``IPv4Address`` or ``IPv6Address`` object if ``is_ip``
          is True, otherwise ``None``.

    Raises:
        HostNormError: If the host is empty, malformed, unsafe, or invalid.
    """
    _validate_raw_host(host)

    # 1. Bracket handling for IPv6 literals
    if host.startswith("["):
        if not host.endswith("]"):
            raise HostNormError(
                f"Malformed bracketed host: missing closing bracket in {host!r}"
            )
        inner = host[1:-1]
        if not inner:
            raise HostNormError("Malformed bracketed host: empty brackets")
        if "[" in inner or "]" in inner:
            raise HostNormError(
                f"Malformed bracketed host: nested or multiple brackets in {host!r}"
            )
        try:
            ip = ipaddress.IPv6Address(inner)
        except ValueError as exc:
            raise HostNormError(
                f"Malformed bracketed host: {inner!r} is not a valid IPv6 literal"
            ) from exc

        if ip.ipv4_mapped is not None:
            mapped_ip = ip.ipv4_mapped
            return NormalizedHost(value=str(mapped_ip), is_ip=True, ip=mapped_ip)
        return NormalizedHost(value=str(ip), is_ip=True, ip=ip)

    if "[" in host or "]" in host:
        raise HostNormError(f"Malformed host: misplaced square brackets in {host!r}")

    # 2. Trailing-dot handling
    if host == ".":
        raise HostNormError("Host cannot be a single dot")
    if host.endswith("."):
        host = host[:-1]
        if host.endswith("."):
            raise HostNormError("Malformed host: multiple trailing dots")
    if host.startswith("."):
        raise HostNormError("Malformed host: leading dot")
    if ".." in host:
        raise HostNormError("Malformed host: empty domain label ('..')")

    # 3. IPv6 without brackets
    if ":" in host:
        try:
            ip = ipaddress.IPv6Address(host)
        except ValueError as exc:
            raise HostNormError(
                f"Invalid host: {host!r} contains a colon but is not a valid IPv6 literal"
            ) from exc

        if ip.ipv4_mapped is not None:
            mapped_ip = ip.ipv4_mapped
            return NormalizedHost(value=str(mapped_ip), is_ip=True, ip=mapped_ip)
        return NormalizedHost(value=str(ip), is_ip=True, ip=ip)

    # 4. IPv4 and legacy IPv4 forms
    if _looks_like_ipv4(host):
        ip = _parse_ipv4_literal(host)
        return NormalizedHost(value=str(ip), is_ip=True, ip=ip)

    # 5. DNS hostname normalization
    canonical_name = normalize_hostname(host)
    return NormalizedHost(value=canonical_name, is_ip=False, ip=None)
