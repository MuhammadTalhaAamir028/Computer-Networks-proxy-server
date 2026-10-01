import ipaddress

import pytest

from proxy.control.hostnorm import (
    HostNormError,
    NormalizedHost,
    normalize_host,
    normalize_hostname,
    parse_ip_literal,
)


def test_normalize_host_returns_canonical_dns_hostname():
    result = normalize_host("WWW.Example.COM")

    assert result == NormalizedHost("www.example.com", False, None)


def test_normalize_hostname_accepts_one_dns_trailing_dot():
    assert normalize_hostname("Example.COM.") == "example.com"
    assert normalize_host("Example.COM.").value == "example.com"


@pytest.mark.parametrize("host", ["", None, 123, "name with spaces", "name\x00x", "name\nx"])
def test_invalid_basic_host_inputs_raise(host):
    with pytest.raises(HostNormError):
        normalize_host(host)


def test_host_length_is_checked_before_normalization():
    with pytest.raises(HostNormError):
        normalize_host("a" * 254)


def test_post_idna_canonical_length_is_checked():
    host = ".".join(["é" * 20] * 10) + ".com"

    assert len(host) <= 253
    with pytest.raises(HostNormError, match="253"):
        normalize_hostname(host)


def test_idna_hostname_is_lowercase_ascii_punycode():
    result = normalize_hostname("BÜCHER.example")

    assert result == "xn--bcher-kva.example"
    assert result.isascii()


@pytest.mark.parametrize(
    "host",
    ["foo_bar.example", "foo..example", ".example", "example..", "-bad.example", "bad-.example"],
)
def test_invalid_dns_labels_are_rejected(host):
    with pytest.raises(HostNormError):
        normalize_hostname(host)


@pytest.mark.parametrize("host", ["zero\u200bwidth.example", "join\u200d.example", "\ufeff.example"])
def test_unicode_format_characters_are_rejected_before_idna(host):
    with pytest.raises(HostNormError):
        normalize_hostname(host)


def test_dns_label_limit_is_enforced_after_idna():
    with pytest.raises(HostNormError):
        normalize_hostname("a" * 64 + ".example")


@pytest.mark.parametrize(
    "text, expected",
    [
        ("127.0.0.1", ipaddress.IPv4Address("127.0.0.1")),
        ("2130706433", ipaddress.IPv4Address("127.0.0.1")),
        ("0x7f000001", ipaddress.IPv4Address("127.0.0.1")),
        ("0177.0.0.1", ipaddress.IPv4Address("127.0.0.1")),
        ("127.1", ipaddress.IPv4Address("127.0.0.1")),
        ("::1", ipaddress.IPv6Address("::1")),
        ("[2001:db8::1]", ipaddress.IPv6Address("2001:db8::1")),
        ("::ffff:127.0.0.1", ipaddress.IPv4Address("127.0.0.1")),
    ],
)
def test_parse_ip_literal_supports_standard_legacy_and_mapped_forms(text, expected):
    assert parse_ip_literal(text) == expected


@pytest.mark.parametrize("text", ["127.0.0.1.", "::1.", "[::1].", "2001:db8::1."])
def test_parse_ip_literal_rejects_trailing_dot_ip_literals(text):
    assert parse_ip_literal(text) is None
    with pytest.raises(HostNormError):
        normalize_host(text)


def test_normalize_host_canonicalizes_ipv4_and_ipv6_literals():
    ipv4 = normalize_host("0x7f000001")
    ipv6 = normalize_host("[2001:0DB8::0001]")

    assert ipv4.is_ip and ipv4.value == "127.0.0.1"
    assert ipv4.ip == ipaddress.IPv4Address("127.0.0.1")
    assert ipv6.is_ip and ipv6.value == "2001:db8::1"
    assert ipv6.ip == ipaddress.IPv6Address("2001:db8::1")


@pytest.mark.parametrize("text", ["[", "]", "[example.com]", "example[com]", "[::1"])
def test_malformed_brackets_are_rejected(text):
    with pytest.raises(HostNormError):
        normalize_host(text)


def test_parse_ip_literal_never_resolves_dns_names():
    assert parse_ip_literal("localhost") is None
    assert parse_ip_literal("example.com") is None


def test_parse_ip_literal_rejects_invalid_and_out_of_range_forms():
    for text in ("999.1.1.1", "4294967296", "256.1.1.1", "1.2.3.4.5", "::gg"):
        assert parse_ip_literal(text) is None


def test_normalized_host_is_immutable():
    result = normalize_host("example.com")

    with pytest.raises((AttributeError, TypeError)):
        result.value = "other"


def test_normalize_hostname_rejects_multiple_trailing_dots():
    with pytest.raises(HostNormError):
        normalize_hostname("example.com..")
