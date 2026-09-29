import re

import pytest

from proxy.control.responses import (
    _build_response,
    _safe_realm,
    _safe_retry_after,
    build_forbidden,
    build_forbidden_response,
    build_proxy_auth_required_response,
    build_too_many_requests_response,
)
from proxy.interfaces import Decision


def split_response(response):
    head, body = response.split(b"\r\n\r\n", 1)
    return head.decode("utf-8"), body


def header_map(header_text):
    lines = header_text.split("\r\n")
    return dict(line.split(": ", 1) for line in lines[1:])


def test_build_response_has_status_headers_body_and_exact_length():
    response = _build_response(
        "HTTP/1.1 200 OK",
        {"X-Test": "value"},
        b"hello",
    )

    head, body = split_response(response)

    assert head == (
        "HTTP/1.1 200 OK\r\n"
        "X-Test: value\r\n"
        "Content-Length: 5\r\n"
        "Connection: close"
    )
    assert body == b"hello"


@pytest.mark.parametrize(
    "headers",
    [
        {"X-Test": "before\r\nafter: injected"},
        {"X\r\nInjected": "value"},
        {"X-Test": "before\nafter"},
        {"X-Test": "before\rafter"},
    ],
)
def test_build_response_rejects_header_injection(headers):
    with pytest.raises(ValueError):
        _build_response("HTTP/1.1 200 OK", headers, b"")


@pytest.mark.parametrize(
    "status_line, headers",
    [
        (b"HTTP/1.1 200 OK", {}),
        ("HTTP/1.1 200 OK", {1: "value"}),
        ("HTTP/1.1 200 OK", {"X-Test": b"value"}),
    ],
)
def test_build_response_rejects_non_string_header_components(status_line, headers):
    with pytest.raises(TypeError):
        _build_response(status_line, headers, b"")


def test_forbidden_response_has_required_status_headers_and_body():
    response = build_forbidden_response(Decision(False, reason="Blocked"))
    head, body = split_response(response)
    headers = header_map(head)

    assert head.startswith("HTTP/1.1 403 Forbidden\r\n")
    assert headers["Content-Type"] == "text/html; charset=utf-8"
    assert headers["Content-Length"] == str(len(body))
    assert headers["Connection"] == "close"
    assert b"<h1>403 Forbidden</h1>" in body
    assert b"Request blocked: Blocked" in body


def test_forbidden_body_html_escapes_dynamic_reason_and_hides_rule():
    reason = '<script>alert("x")</script> & denied'
    response = build_forbidden_response(
        Decision(False, reason=reason, rule="secret:internal-rule")
    )
    _, body = split_response(response)
    body_text = body.decode("utf-8")

    assert "<script>" not in body_text
    assert "&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;" in body_text
    assert "&amp; denied" in body_text
    assert "internal-rule" not in body_text


def test_forbidden_reason_default_is_safe():
    _, body = split_response(build_forbidden_response(Decision(False)))

    assert b"Request blocked: Forbidden" in body


def test_forbidden_alias_matches_primary_builder():
    decision = Decision(False, reason="policy")

    assert build_forbidden(decision) == build_forbidden_response(decision)


def test_proxy_auth_response_has_exact_empty_body_framing():
    response = build_proxy_auth_required_response()
    head, body = split_response(response)
    headers = header_map(head)

    assert head.startswith("HTTP/1.1 407 Proxy Authentication Required\r\n")
    assert headers["Proxy-Authenticate"] == 'Basic realm="proxy"'
    assert headers["Content-Length"] == "0"
    assert headers["Connection"] == "close"
    assert body == b""


def test_proxy_auth_response_escapes_quotes_and_backslashes():
    response = build_proxy_auth_required_response('my "proxy"\\realm')
    head, _ = split_response(response)

    assert 'Proxy-Authenticate: Basic realm="my \\"proxy\\"\\\\realm"' in head


@pytest.mark.parametrize("realm", [None, 123, b"proxy", object()])
def test_proxy_auth_response_rejects_non_string_realm(realm):
    with pytest.raises(TypeError):
        build_proxy_auth_required_response(realm)


@pytest.mark.parametrize("realm", ["bad\r\nInjected: yes", "bad\n", "bad\r", "bad\x00"])
def test_proxy_auth_response_rejects_control_characters(realm):
    with pytest.raises(ValueError):
        build_proxy_auth_required_response(realm)


def test_safe_realm_preserves_unicode_and_escapes_delimiters():
    assert _safe_realm('代理 "realm"\\x') == '代理 \\"realm\\"\\\\x'


# @pytest.mark.parametrize("retry_after, expected", [(60, 60), (0, 0), (-5, 0)])
# def test_safe_retry_after_accepts_integers_and_clamps_negative_values(
#     retry_after, expected
# ):
#     assert _safe_retry_after(retry_after) == expected


# @pytest.mark.parametrize("retry_after", [True, False, 60.9, "60", None, b"60"])
# def test_safe_retry_after_rejects_non_integer_values(retry_after):
#     with pytest.raises(TypeError):
#         _safe_retry_after(retry_after)

@pytest.mark.parametrize("retry_after, expected", [(60, 60), (0, 0)])
def test_safe_retry_after_accepts_non_negative_integers(
    retry_after, expected
):
    assert _safe_retry_after(retry_after) == expected


def test_safe_retry_after_rejects_negative_integers():
    with pytest.raises(ValueError):
        _safe_retry_after(-5)


@pytest.mark.parametrize(
    "retry_after",
    [True, False, 60.9, "60", None, b"60"],
)
def test_safe_retry_after_rejects_non_integer_values(retry_after):
    with pytest.raises(TypeError):
        _safe_retry_after(retry_after)


def test_too_many_requests_response_has_exact_retry_and_framing():
    response = build_too_many_requests_response(60)
    head, body = split_response(response)
    headers = header_map(head)

    assert head.startswith("HTTP/1.1 429 Too Many Requests\r\n")
    assert headers["Retry-After"] == "60"
    assert headers["Content-Length"] == "0"
    assert headers["Connection"] == "close"
    assert body == b""


# @pytest.mark.parametrize("retry_after", [0, -1, -999999])
# def test_too_many_requests_normalizes_negative_retry_to_zero(retry_after):
#     head, body = split_response(build_too_many_requests_response(retry_after))
#     headers = header_map(head)

#     assert headers["Retry-After"] == "0"
#     assert headers["Content-Length"] == "0"
#     assert body == b""

@pytest.mark.parametrize("retry_after", [0])
def test_too_many_requests_accepts_zero_retry(retry_after):
    head, body = split_response(build_too_many_requests_response(retry_after))
    headers = header_map(head)

    assert headers["Retry-After"] == "0"
    assert headers["Content-Length"] == "0"
    assert body == b""


@pytest.mark.parametrize("retry_after", [-1, -999999])
def test_too_many_requests_rejects_negative_retry(retry_after):
    with pytest.raises(ValueError):
        build_too_many_requests_response(retry_after)


@pytest.mark.parametrize("retry_after", [True, 60.9, "60", None])
def test_too_many_requests_rejects_invalid_retry_type(retry_after):
    with pytest.raises(TypeError):
        build_too_many_requests_response(retry_after)


def test_public_outputs_never_contain_header_injection_sequences():
    responses = [
        build_forbidden_response(Decision(False, reason="safe")),
        build_proxy_auth_required_response("safe"),
        build_too_many_requests_response(1),
    ]

    for response in responses:
        header, _ = split_response(response)
        assert "\r\n\r\n" not in header
        assert re.search(r"\r\n[A-Za-z-]+: ", header)
