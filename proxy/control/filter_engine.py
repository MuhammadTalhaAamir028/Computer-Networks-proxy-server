"""
proxy.control.filter_engine
~~~~~~~~~~~~~~~~~~~~~~~~~~~
Central policy evaluation layer for Member 2's Traffic Control & Security subsystem.

Evaluates incoming requests against configured filtering and access-control rules:
- Host normalization and validation (via ``proxy.control.hostnorm``)
- SSRF guard (blocking private, loopback, link-local, and reserved addresses)
- Port filtering (blocked ports and allowed port sets)
- Domain filtering (exact, subdomain wildcard, denylist, and allowlist modes)
- URL/path regex filtering (plain HTTP only, truncated to 2048 chars, safe regexes)

Implements the frozen ``FilterEngine`` protocol from ``proxy.interfaces``.
This module contains pure policy evaluation logic and NEVER performs DNS
resolution, opens sockets, or sends HTTP network requests.

Public API
----------
- ``FilterEngine``   – Thread-safe policy evaluation engine.
- ``build_filter``   – Factory function constructing a ``FilterEngine`` from config.
- ``FilterDecision`` – Alias for ``proxy.interfaces.Decision``.
"""
from __future__ import annotations

import ipaddress
import logging
import re
from dataclasses import dataclass
from typing import Any, Optional, Sequence, Tuple, Union

from proxy.control.hostnorm import (
    HostNormError,
    IPAddress,
    NormalizedHost,
    normalize_host,
    parse_ip_literal,
)
from proxy.interfaces import Decision

__all__ = ["FilterEngine", "build_filter", "FilterDecision"]

_log = logging.getLogger(__name__)

# Alias for compatibility with callers expecting FilterDecision
FilterDecision = Decision


def _has_nested_quantifiers(pattern: str) -> bool:
    """Detect nested quantifiers such as ``(a+)+`` or ``(.*)*`` (ReDoS risk).

    Scans the pattern ignoring escaped characters to check if an unescaped
    group contains a repeating quantifier (* or +) and is itself repeated
    by an outer repeating quantifier (* or +).
    """
    cleaned = re.sub(r"\\.", "", pattern)
    stack = []
    repeat_quantifiers = {"*", "+"}
    for i, c in enumerate(cleaned):
        if c == "(":
            stack.append(False)
        elif c == ")" and stack:
            has_quant = stack.pop()
            if i + 1 < len(cleaned) and (
                cleaned[i + 1] in repeat_quantifiers
                or (cleaned[i + 1] == "{" and "," in cleaned[i + 1 : i + 10])
            ):
                if has_quant:
                    return True
                if stack:
                    stack[-1] = True
            else:
                if has_quant and stack:
                    stack[-1] = True
        elif c in repeat_quantifiers:
            if stack:
                stack[-1] = True
    return False


def _matches_domain_pattern(host: str, pattern: str) -> bool:
    """Check if normalized *host* matches domain *pattern*.

    Wildcard semantics (B4.3):
    - ``example.com`` matches only itself.
    - ``*.example.com`` matches any subdomain at any depth (e.g.
      ``sub.example.com``, ``a.b.example.com``), but NOT ``example.com`` itself.
    - ``evilexample.com`` must NOT match ``*.example.com``.
    """
    if pattern.startswith("*."):
        suffix = pattern[1:]  # e.g. ".example.com"
        return host.endswith(suffix) and len(host) > len(suffix)
    return host == pattern


@dataclass(frozen=True)
class _CompiledRules:
    """Immutable snapshot of compiled filtering rules."""

    mode: str
    deny_domains: Tuple[str, ...]
    allow_domains: Tuple[str, ...]
    blocked_ports: frozenset[int]
    allowed_ports: frozenset[int]
    deny_url_regex: Tuple[Tuple[str, re.Pattern[str]], ...]
    block_private_ips: bool
    private_allow: frozenset[Tuple[str, int]]
    raw_private_allow: Tuple[str, ...]


class FilterEngine:
    """Thread-safe request and destination policy evaluation engine.

    Satisfies the ``proxy.interfaces.FilterEngine`` protocol.
    Reads immutable compiled rule snapshots lock-free.
    Updates compiled rules atomically when configuration reloads.
    """

    def __init__(self, config: Any) -> None:
        """Initialize filter engine from configuration object.

        Args:
            config: A configuration object (such as ``proxy.control.config.Config``)
                or dict providing filter settings.

        Raises:
            ValueError: If configuration values or regular expressions are malformed.
        """
        self._compiled_rules: _CompiledRules = self._compile_rules(config)

        # Register for atomic configuration reload notifications if supported
        if hasattr(config, "add_reload_listener") and callable(
            config.add_reload_listener
        ):
            config.add_reload_listener(self._on_config_reload)

    def _on_config_reload(self, config: Any) -> None:
        """Callback invoked after a successful configuration reload."""
        try:
            new_rules = self._compile_rules(config)
            self._compiled_rules = new_rules  # Atomic reference swap
        except Exception as exc:
            _log.exception("Failed to recompile filter rules on reload: %s", exc)

    @staticmethod
    def _get_config_val(config: Any, key: str, default: Any = None) -> Any:
        """Helper to read dotted keys from Config object or dict."""
        if isinstance(config, dict):
            cur: Any = config
            for part in key.split("."):
                if not isinstance(cur, dict) or part not in cur:
                    return default
                cur = cur[part]
            return cur
        if hasattr(config, "get") and callable(config.get):
            return config.get(key, default)
        return default

    @classmethod
    def _compile_rules(cls, config: Any) -> _CompiledRules:
        """Compile and validate filtering rules into an immutable snapshot."""
        # 1. Mode
        mode = cls._get_config_val(config, "filter.mode", "denylist")
        if mode not in ("denylist", "allowlist"):
            raise ValueError(
                f"Invalid filter mode: {mode!r}. Must be 'denylist' or 'allowlist'."
            )

        # 2. Domain lists
        def _compile_domain_list(key: str) -> Tuple[str, ...]:
            raw_list = cls._get_config_val(config, key, [])
            if not isinstance(raw_list, (list, tuple)):
                raise ValueError(f"{key} must be a list of strings")
            compiled = []
            for item in raw_list:
                if not isinstance(item, str):
                    raise ValueError(f"{key} items must be strings: {item!r}")
                item_str = item.strip().lower()
                if item_str.endswith("."):
                    item_str = item_str[:-1]
                if not item_str:
                    continue
                if "*" in item_str:
                    if not item_str.startswith("*.") or item_str.count("*") > 1 or len(item_str) <= 2:
                        raise ValueError(
                            f"Invalid wildcard domain in {key}: {item!r}. "
                            "Only a leading '*.' is permitted."
                        )
                compiled.append(item_str)
            return tuple(compiled)

        deny_domains = _compile_domain_list("filter.deny_domains")
        allow_domains = _compile_domain_list("filter.allow_domains")

        # 3. Port lists
        def _compile_port_set(key: str, default: Sequence[int]) -> frozenset[int]:
            raw_ports = cls._get_config_val(config, key, default)
            if not isinstance(raw_ports, (list, tuple, set, frozenset)):
                raise ValueError(f"{key} must be a list of integers")
            ports = set()
            for p in raw_ports:
                if not isinstance(p, int) or isinstance(p, bool) or p < 1 or p > 65535:
                    raise ValueError(f"Invalid port in {key}: {p!r} (must be 1-65535)")
                ports.add(p)
            return frozenset(ports)

        blocked_ports = _compile_port_set("filter.blocked_ports", [25])
        allowed_ports = _compile_port_set("filter.allowed_ports", [])

        # 4. URL regex rules
        raw_regex_list = cls._get_config_val(config, "filter.deny_url_regex", [])
        if not isinstance(raw_regex_list, (list, tuple)):
            raise ValueError("filter.deny_url_regex must be a list of strings")
        compiled_regex = []
        for pat in raw_regex_list:
            if not isinstance(pat, str):
                raise ValueError(f"Regex pattern must be a string: {pat!r}")
            if len(pat) > 200:
                raise ValueError(
                    f"Regex pattern exceeds 200 characters limit ({len(pat)}): {pat!r}"
                )
            if _has_nested_quantifiers(pat):
                raise ValueError(
                    f"Dangerous nested quantifiers detected in regex pattern: {pat!r}"
                )
            try:
                c_re = re.compile(pat, re.IGNORECASE)
                compiled_regex.append((pat, c_re))
            except re.error as exc:
                raise ValueError(f"Failed to compile URL regex {pat!r}: {exc}") from exc

        # 5. SSRF guard & private allow
        block_private_ips = cls._get_config_val(
            config, "filter.block_private_ips", True
        )
        if not isinstance(block_private_ips, bool):
            raise ValueError("filter.block_private_ips must be a boolean")
        raw_private_allow = cls._get_config_val(config, "filter.private_allow", [])
        if not isinstance(raw_private_allow, (list, tuple)):
            raise ValueError("filter.private_allow must be a list of 'host:port' strings")

        private_allow_set = set()
        for entry in raw_private_allow:
            if not isinstance(entry, str):
                raise ValueError(f"private_allow entry must be a string: {entry!r}")
            entry_clean = entry.strip()
            if not entry_clean:
                raise ValueError("private_allow entries must not be empty")
            if ":" not in entry_clean:
                raise ValueError(f"Invalid private_allow entry (missing port): {entry!r}")
            h_part, p_part = entry_clean.rsplit(":", 1)
            try:
                port_num = int(p_part)
                if port_num < 1 or port_num > 65535:
                    raise ValueError
            except ValueError:
                raise ValueError(f"Invalid port in private_allow entry: {entry!r}")

            h_norm = h_part.strip()
            try:
                norm_obj = normalize_host(h_norm)
            except (HostNormError, ValueError, TypeError) as exc:
                raise ValueError(
                    f"Invalid host in private_allow entry: {entry!r}"
                ) from exc
            private_allow_set.add((norm_obj.value, port_num))

        return _CompiledRules(
            mode=mode,
            deny_domains=deny_domains,
            allow_domains=allow_domains,
            blocked_ports=blocked_ports,
            allowed_ports=allowed_ports,
            deny_url_regex=tuple(compiled_regex),
            block_private_ips=block_private_ips,
            private_allow=frozenset(private_allow_set),
            raw_private_allow=tuple(raw_private_allow),
        )

    # ── Protocol Implementation ───────────────────────────────

    def check(
        self,
        host: str,
        port: int,
        path: Optional[str] = None,
        method: str = "GET",
    ) -> Decision:
        """Evaluate an incoming request against filtering policy.

        Evaluation order (first match wins, per B4.3):
        1. Normalize host (via ``hostnorm``). Malformed hosts are rejected.
        2. SSRF guard (if enabled, block loopback/private/reserved addresses
           and localhost names unless exempted by ``private_allow``).
        3. Port rules (blocked ports, or non-empty allowed ports).
        4. Domain rules (denylist or allowlist matching).
        5. URL regex (plain HTTP only, matching host+path up to 2048 chars).
        6. Allow request.

        This method never raises an exception on bad input.
        """
        # Validate port type and range
        if not isinstance(port, int) or isinstance(port, bool) or port < 1 or port > 65535:
            return Decision(False, reason="Invalid port number", rule="invalid:port")

        # Step 1: Normalize host
        try:
            norm = normalize_host(host)
        except (HostNormError, ValueError, TypeError) as exc:
            return Decision(
                False,
                reason=f"Invalid host header or address: {exc}",
                rule="invalid:host",
            )

        rules = self._compiled_rules

        # Step 2: SSRF guard
        if rules.block_private_ips:
            is_restricted = False
            if norm.is_ip and norm.ip is not None:
                ip = norm.ip
                is_restricted = (
                    ip.is_loopback
                    or ip.is_private
                    or ip.is_link_local
                    or ip.is_reserved
                    or ip.is_multicast
                    or ip.is_unspecified
                )
            else:
                h_val = norm.value
                is_restricted = (
                    h_val == "localhost"
                    or h_val.endswith(".localhost")
                    or h_val == "0.0.0.0"
                )

            if is_restricted:
                exempted = (norm.value, port) in rules.private_allow or (
                    str(host).strip().lower(),
                    port,
                ) in rules.private_allow
                if not exempted:
                    return Decision(
                        False,
                        reason="Destination IP or host is not allowed (SSRF guard)",
                        rule="ssrf:private_ip",
                    )

        # Step 3: Port rules
        if port in rules.blocked_ports:
            return Decision(
                False, reason=f"Port {port} is blocked", rule=f"port:blocked:{port}"
            )

        if rules.allowed_ports and port not in rules.allowed_ports:
            return Decision(
                False,
                reason=f"Port {port} is not allowed",
                rule=f"port:not_allowed:{port}",
            )

        # Step 4: Domain rules
        if rules.mode == "denylist":
            for pat in rules.deny_domains:
                if _matches_domain_pattern(norm.value, pat):
                    return Decision(
                        False,
                        reason=f"Domain {norm.value} is blocked by rule {pat}",
                        rule=f"deny:domain:{pat}",
                    )
        elif rules.mode == "allowlist":
            matched = False
            for pat in rules.allow_domains:
                if _matches_domain_pattern(norm.value, pat):
                    matched = True
                    break
            if not matched:
                return Decision(
                    False,
                    reason=f"Domain {norm.value} is not in allowlist",
                    rule="allow:none",
                )

        # Step 5: URL regex (plain HTTP only when path is not None)
        if path is not None and rules.deny_url_regex:
            target = (norm.value + path)[:2048]
            for pat_str, compiled_re in rules.deny_url_regex:
                if compiled_re.search(target):
                    return Decision(
                        False,
                        reason="Request URL matches blocked pattern",
                        rule=f"deny:url:{pat_str}",
                    )

        # Step 6: Allow
        return Decision(True, reason="Request allowed", rule=None)

    def check_ip(self, ip: str, port: int) -> Decision:
        """Evaluate an already-resolved destination IP before establishing connection.

        Invoked by core networking for each resolved IP to protect against
        DNS rebinding and SSRF tricks. Never invokes DNS resolution.
        """
        # Validate port
        if not isinstance(port, int) or isinstance(port, bool) or port < 1 or port > 65535:
            return Decision(False, reason="Invalid port number", rule="invalid:port")

        if not isinstance(ip, str) or not ip.strip():
            return Decision(False, reason="Invalid IP address", rule="invalid:ip")

        # Parse IP address
        parsed_ip = parse_ip_literal(ip.strip())
        if parsed_ip is None:
            try:
                raw_ip = ipaddress.ip_address(ip.strip())
                if getattr(raw_ip, "ipv4_mapped", None) is not None:
                    parsed_ip = raw_ip.ipv4_mapped
                else:
                    parsed_ip = raw_ip
            except ValueError:
                return Decision(False, reason="Invalid IP address", rule="invalid:ip")

        rules = self._compiled_rules

        # SSRF guard on resolved IP
        if rules.block_private_ips:
            is_restricted = (
                parsed_ip.is_loopback
                or parsed_ip.is_private
                or parsed_ip.is_link_local
                or parsed_ip.is_reserved
                or parsed_ip.is_multicast
                or parsed_ip.is_unspecified
            )
            if is_restricted:
                ip_str = str(parsed_ip)
                exempted = (ip_str, port) in rules.private_allow or (
                    ip.strip().lower(),
                    port,
                ) in rules.private_allow
                if not exempted:
                    return Decision(
                        False,
                        reason="Resolved IP address is blocked (SSRF guard)",
                        rule="ssrf:private_ip",
                    )

        # Port rules
        if port in rules.blocked_ports:
            return Decision(
                False, reason=f"Port {port} is blocked", rule=f"port:blocked:{port}"
            )

        if rules.allowed_ports and port not in rules.allowed_ports:
            return Decision(
                False,
                reason=f"Port {port} is not allowed",
                rule=f"port:not_allowed:{port}",
            )

        return Decision(True, reason="Resolved IP allowed", rule=None)

    def describe(self) -> dict:
        """Return a small, JSON-safe dictionary describing current rules.

        Backed by ``GET /rules`` in the Admin API for the UI dashboard.
        Contains no secrets.
        """
        rules = self._compiled_rules
        return {
            "mode": rules.mode,
            "block_private_ips": rules.block_private_ips,
            "deny_domains": list(rules.deny_domains),
            "allow_domains": list(rules.allow_domains),
            "blocked_ports": sorted(rules.blocked_ports),
            "allowed_ports": sorted(rules.allowed_ports),
            "deny_url_regex": [pat for pat, _ in rules.deny_url_regex],
            "private_allow": sorted(rules.raw_private_allow),
        }

    def forbidden_response(self, decision: Decision) -> bytes:
        """Delegate 403 response construction to the response layer."""
        from proxy.control.responses import build_forbidden

        return build_forbidden(decision)


def build_filter(config: Any) -> FilterEngine:
    """Build and return the configured rules/filter engine.

    Factory function matching the specification in Section A6.3 and consumed
    by ``proxy.control.build_filter``.
    """
    return FilterEngine(config)
