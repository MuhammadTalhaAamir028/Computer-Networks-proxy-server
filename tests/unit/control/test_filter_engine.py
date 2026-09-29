import ipaddress

import pytest

from proxy.control.filter_engine import FilterEngine, build_filter
from proxy.interfaces import Decision
from proxy.stubs import DictConfig


def config(**filter_values):
    values = {
        "mode": "denylist",
        "deny_domains": [],
        "allow_domains": [],
        "blocked_ports": [25],
        "allowed_ports": [],
        "deny_url_regex": [],
        "block_private_ips": True,
        "private_allow": [],
    }
    values.update(filter_values)
    return DictConfig({"filter": values})


def engine(**filter_values):
    return FilterEngine(config(**filter_values))


def assert_blocked(decision, rule):
    assert isinstance(decision, Decision)
    assert not decision.allowed
    assert decision.rule == rule


def test_factory_builds_filter_engine():
    assert isinstance(build_filter(config()), FilterEngine)


def test_default_public_request_is_allowed():
    decision = engine().check("example.com", 80, "/", "GET")

    assert decision == Decision(True, reason="Request allowed", rule=None)


@pytest.mark.parametrize(
    "host",
    ["", "bad host", "bad\x00host", "bad\nhost", "a" * 254, None],
)
def test_invalid_host_is_blocked_without_raising(host):
    decision = engine(block_private_ips=False).check(host, 80, "/", "GET")

    assert_blocked(decision, "invalid:host")


@pytest.mark.parametrize("port", [0, 65536, -1, True, "80", None])
def test_invalid_port_is_blocked_without_raising(port):
    decision = engine().check("example.com", port, "/", "GET")

    assert_blocked(decision, "invalid:port")


def test_blocked_port_takes_precedence_over_domain_rules():
    decision = engine(
        blocked_ports=[80],
        deny_domains=["example.com"],
        block_private_ips=False,
    ).check("example.com", 80, "/", "GET")

    assert_blocked(decision, "port:blocked:80")


def test_allowed_ports_block_unlisted_port():
    decision = engine(
        blocked_ports=[],
        allowed_ports=[443],
        block_private_ips=False,
    ).check("example.com", 80, "/", "GET")

    assert_blocked(decision, "port:not_allowed:80")


def test_allowed_port_passes_port_policy():
    decision = engine(
        blocked_ports=[],
        allowed_ports=[443],
        block_private_ips=False,
    ).check("example.com", 443, "/", "GET")

    assert decision.allowed


@pytest.mark.parametrize(
    "host, expected_rule",
    [
        ("ads.example.com", "deny:domain:ads.example.com"),
        ("ADS.EXAMPLE.COM.", "deny:domain:ads.example.com"),
        ("sub.ads.example.com", "deny:domain:*.ads.example.com"),
        ("a.b.ads.example.com", "deny:domain:*.ads.example.com"),
    ],
)
def test_domain_denylist_matching(host, expected_rule):
    patterns = ["ads.example.com", "*.ads.example.com"]

    decision = engine(
        deny_domains=patterns, block_private_ips=False
    ).check(host, 80, "/", "GET")

    assert_blocked(decision, expected_rule)


@pytest.mark.parametrize("host", ["example.com", "evilexample.com"])
def test_wildcard_does_not_match_apex_or_suffix_trap(host):
    decision = engine(
        deny_domains=["*.example.com"], block_private_ips=False
    ).check(host, 80, "/", "GET")

    assert decision.allowed


def test_allowlist_allows_matching_domain_and_blocks_other_domain():
    filter_engine = engine(
        mode="allowlist",
        allow_domains=["example.com", "*.trusted.example"],
        block_private_ips=False,
    )

    assert filter_engine.check("example.com", 80, "/", "GET").allowed
    assert filter_engine.check("api.trusted.example", 80, "/", "GET").allowed
    assert_blocked(
        filter_engine.check("other.example", 80, "/", "GET"),
        "allow:none",
    )


def test_invalid_mode_and_wildcard_configuration_are_rejected():
    with pytest.raises(ValueError):
        engine(mode="unknown")
    with pytest.raises(ValueError):
        engine(deny_domains=["example.*.com"])
    with pytest.raises(ValueError):
        engine(deny_domains=["example.com*"])


def test_url_regex_blocks_plain_http_path():
    decision = engine(
        deny_url_regex=[r"secret"],
        block_private_ips=False,
    ).check("example.com", 80, "/secret/data", "GET")

    assert_blocked(decision, "deny:url:secret")


def test_url_regex_is_ignored_for_connect_path_none():
    decision = engine(
        deny_url_regex=[r"secret"],
        block_private_ips=False,
    ).check("example.com", 443, None, "CONNECT")

    assert decision.allowed


def test_url_regex_is_case_insensitive_and_limited_to_2048_characters():
    filter_engine = engine(
        deny_url_regex=[r"blocked"],
        block_private_ips=False,
    )

    assert not filter_engine.check("example.com", 80, "/BLOCKED", "GET").allowed
    path = "/" + ("x" * 2050) + "blocked"
    assert filter_engine.check("example.com", 80, path, "GET").allowed


@pytest.mark.parametrize(
    "patterns",
    [
        ["["],
        ["a" * 201],
        [r"(a+)+"],
        [r"(.*)*"],
    ],
)
def test_unsafe_url_regex_configuration_is_rejected(patterns):
    with pytest.raises(ValueError):
        engine(deny_url_regex=patterns)


@pytest.mark.parametrize(
    "host",
    [
        "127.0.0.1",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.169.254",
        "::1",
        "fc00::1",
        "::ffff:127.0.0.1",
        "2130706433",
        "0x7f000001",
        "127.1",
        "0177.0.0.1",
        "localhost",
        "a.localhost",
        "0.0.0.0",
    ],
)
def test_ssrf_guard_blocks_private_and_local_destinations(host):
    decision = engine().check(host, 80, "/", "GET")

    assert_blocked(decision, "ssrf:private_ip")


def test_private_allow_exempts_exact_normalized_host_and_port():
    filter_engine = engine(private_allow=["127.0.0.1:8080"])

    assert filter_engine.check("127.0.0.1", 8080, "/", "GET").allowed
    assert_blocked(
        filter_engine.check("127.0.0.1", 8081, "/", "GET"),
        "ssrf:private_ip",
    )


@pytest.mark.parametrize("entry", ["", "bad", "host:notaport", "host:0", "host:65536"])
def test_malformed_private_allow_is_rejected(entry):
    with pytest.raises(ValueError):
        engine(private_allow=[entry])


def test_private_allow_invalid_host_is_rejected_not_retained():
    with pytest.raises(ValueError):
        engine(private_allow=["bad host:8080"])


@pytest.mark.parametrize("value", ["false", 1, 0, None, [], ""])
def test_block_private_ips_requires_actual_boolean(value):
    with pytest.raises(ValueError):
        engine(block_private_ips=value)


def test_disabling_private_ip_guard_allows_private_host():
    decision = engine(block_private_ips=False).check("127.0.0.1", 80, "/", "GET")

    assert decision.allowed


@pytest.mark.parametrize("ip", ["127.0.0.1", "10.0.0.1", "192.168.1.1", "::1"])
def test_check_ip_blocks_resolved_private_addresses(ip):
    decision = engine().check_ip(ip, 80)

    assert_blocked(decision, "ssrf:private_ip")


def test_check_ip_allows_public_address():
    decision = engine().check_ip("93.184.216.34", 80)

    assert decision == Decision(True, reason="Resolved IP allowed", rule=None)


def test_check_ip_applies_port_rules():
    filter_engine = engine(blocked_ports=[80], block_private_ips=False)

    assert_blocked(filter_engine.check_ip("93.184.216.34", 80), "port:blocked:80")


@pytest.mark.parametrize("ip", ["", "not-an-ip", None, "[::1"])
def test_check_ip_rejects_invalid_ip(ip):
    decision = engine().check_ip(ip, 80)

    assert_blocked(decision, "invalid:ip")


def test_method_is_forwarded_but_not_an_implicit_policy_dimension():
    filter_engine = engine(block_private_ips=False)

    assert filter_engine.check("example.com", 80, "/", "DELETE").allowed


def test_describe_is_json_safe_and_contains_compiled_policy():
    filter_engine = engine(
        deny_domains=["example.com"],
        blocked_ports=[25, 80],
        allowed_ports=[443],
        deny_url_regex=["secret"],
        private_allow=["127.0.0.1:8080"],
    )

    description = filter_engine.describe()

    assert description["mode"] == "denylist"
    assert description["deny_domains"] == ["example.com"]
    assert description["blocked_ports"] == [25, 80]
    assert description["allowed_ports"] == [443]
    assert description["deny_url_regex"] == ["secret"]
    assert description["private_allow"] == ["127.0.0.1:8080"]


def test_forbidden_response_delegates_to_response_layer():
    response = engine().forbidden_response(Decision(False, reason="blocked"))

    assert response.startswith(b"HTTP/1.1 403 Forbidden\r\n")
    assert b"blocked" in response


def test_reload_callback_atomically_replaces_rules():
    class ReloadableConfig(DictConfig):
        def add_reload_listener(self, callback):
            self.callback = callback

    cfg = ReloadableConfig(config(block_private_ips=False)._d)
    filter_engine = FilterEngine(cfg)
    assert filter_engine.check("example.com", 80, "/", "GET").allowed

    cfg._d["filter"]["deny_domains"] = ["example.com"]
    cfg.callback(cfg)

    assert not filter_engine.check("example.com", 80, "/", "GET").allowed


def test_private_allow_uses_ipv6_normalization():
    filter_engine = engine(private_allow=["[::1]:8080"])

    assert filter_engine.check("::1", 8080, "/", "GET").allowed


def test_ip_policy_uses_parsed_ip_properties_without_dns():
    filter_engine = engine()
    result = filter_engine.check_ip(str(ipaddress.ip_address("8.8.8.8")), 80)

    assert result.allowed
