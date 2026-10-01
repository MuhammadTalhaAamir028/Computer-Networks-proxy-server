import base64
import hashlib
import re
from collections import OrderedDict

import pytest

from proxy.control.auth import (
    SCRYPT,
    Authenticator,
    build_auth,
    hash_password,
)
from proxy.interfaces import AuthResult
from proxy.stubs import DictConfig


class FakeClock:
    def __init__(self, value=1000.0):
        self.value = value

    def __call__(self):
        return self.value

    def advance(self, seconds):
        self.value += seconds


def credentials(password="correct-password", username="alice"):
    salt = b"0123456789abcdef"
    return {
        username: {
            "salt": salt.hex(),
            "hash": hash_password(password.encode("utf-8"), salt).hex(),
        }
    }


def config(
    users=None,
    *,
    enabled=True,
    max_failures=3,
    lockout_seconds=60,
    failure_window_seconds=300,
    realm="proxy",
):
    return DictConfig(
        {
            "auth": {
                "enabled": enabled,
                "realm": realm,
                "users": credentials() if users is None else users,
                "max_failures": max_failures,
                "lockout_seconds": lockout_seconds,
                "failure_window_seconds": failure_window_seconds,
            }
        }
    )


def auth_header(username="alice", password="correct-password", scheme="Basic"):
    token = base64.b64encode(f"{username}:{password}".encode("utf-8"))
    return {"proxy-authorization": f"{scheme} {token.decode('ascii')}"}


def result_for(authenticator, username="alice", password="correct-password"):
    return authenticator.check(auth_header(username, password), "192.0.2.10")


def test_scrypt_parameters_and_helper_match_standard_library():
    salt = b"0123456789abcdef"

    assert SCRYPT == {"n": 2**14, "r": 8, "p": 1, "dklen": 32}
    assert hash_password(b"password", salt) == hashlib.scrypt(
        b"password", salt=salt, **SCRYPT
    )


def test_valid_login_returns_success_and_username():
    result = result_for(Authenticator(config()))

    assert result == AuthResult(ok=True, user="alice")


def test_wrong_password_is_rejected_and_recorded():
    authenticator = Authenticator(config())

    result = result_for(authenticator, password="wrong")

    assert result == AuthResult(ok=False, user="alice", reason="bad_creds")
    assert authenticator.recent_failures()[-1]["reason"] == "bad_creds"


def test_unknown_user_is_rejected_without_revealing_user_in_history():
    authenticator = Authenticator(config())

    result = result_for(authenticator, username="unknown")

    assert result == AuthResult(ok=False, user="unknown", reason="bad_creds")
    assert authenticator.recent_failures()[-1]["user"] == "unknown"


@pytest.mark.parametrize(
    "headers, reason",
    [
        ({}, "missing"),
        (None, "malformed"),
        ({"proxy-authorization": None}, "missing"),
        ({"proxy-authorization": "Bearer token"}, "malformed"),
        ({"proxy-authorization": "Basic !!!"}, "malformed"),
        ({"proxy-authorization": "Basic " + base64.b64encode(b"alice").decode()}, "malformed"),
        (
            {"proxy-authorization": "Basic " + base64.b64encode(b"alice:\xff").decode()},
            "malformed",
        ),
    ],
)
def test_missing_and_malformed_headers_return_safe_reasons(headers, reason):
    authenticator = Authenticator(config())

    result = authenticator.check(headers, "192.0.2.10")

    assert result == AuthResult(ok=False, reason=reason)


def test_basic_scheme_is_case_insensitive():
    authenticator = Authenticator(config())
    result = authenticator.check(
        auth_header(scheme="bAsIc"), "192.0.2.10"
    )

    assert result.ok and result.user == "alice"


def test_colon_in_password_is_preserved():
    password = "part-one:part-two"
    authenticator = Authenticator(config(credentials(password=password)))

    result = result_for(authenticator, password=password)

    assert result.ok


def test_non_ascii_username_and_password_use_utf8():
    username = "用户"
    password = "пароль-密码"
    authenticator = Authenticator(
        config(credentials(username=username, password=password))
    )

    result = result_for(authenticator, username=username, password=password)

    assert result.ok and result.user == username


def test_oversized_header_is_rejected():
    authenticator = Authenticator(config())

    result = authenticator.check(
        {"proxy-authorization": "Basic " + "A" * 600},
        "192.0.2.10",
    )

    assert result.reason == "malformed"


def test_disabled_auth_accepts_any_input_without_state_change():
    authenticator = Authenticator(config(enabled=False))

    result = authenticator.check({"proxy-authorization": "not valid"}, "ip")

    assert result == AuthResult(ok=True)
    assert authenticator.recent_failures() == []
    assert authenticator._cache == {}


def test_successful_credentials_are_cached(monkeypatch):
    authenticator = Authenticator(config())
    first = result_for(authenticator)
    monkeypatch.setattr(authenticator, "_verify", lambda *_args: False)

    second = result_for(authenticator)

    assert first.ok and second == AuthResult(ok=True, user="alice")


def test_expired_cached_credentials_are_verified_again():
    clock = FakeClock()
    authenticator = Authenticator(config(), clock=clock)

    assert result_for(authenticator).ok
    clock.advance(301)

    result = result_for(authenticator)

    assert result.ok


def test_success_clears_previous_failures():
    authenticator = Authenticator(config(max_failures=3))
    result_for(authenticator, password="wrong")

    assert result_for(authenticator).ok
    assert authenticator._failures == {}


def test_failures_are_not_cached():
    authenticator = Authenticator(config())

    result_for(authenticator, password="wrong")

    assert authenticator._cache == {}


def test_unknown_and_known_verification_each_run_one_derived_hash(monkeypatch):
    authenticator = Authenticator(config())
    calls = []

    def derive(password, salt):
        calls.append((password, salt))
        return b"x" * 32

    monkeypatch.setattr(authenticator, "_derive", derive)
    assert not authenticator._verify("unknown", b"password")
    assert len(calls) == 1

    calls.clear()
    assert not authenticator._verify("alice", b"password")
    assert len(calls) == 1


def test_lockout_threshold_attempt_is_bad_credentials_then_next_is_locked():
    clock = FakeClock()
    authenticator = Authenticator(config(max_failures=2), clock=clock)

    first = result_for(authenticator, password="wrong")
    second = result_for(authenticator, password="wrong")
    third = authenticator.check({}, "192.0.2.10")

    assert first.reason == "bad_creds"
    assert second.reason == "bad_creds"
    assert not second.locked
    assert third.reason == "locked"
    assert third.locked and third.user is None
    assert third.retry_after == 60


def test_locked_ip_is_rejected_before_header_parsing():
    authenticator = Authenticator(config(max_failures=1))
    assert not result_for(authenticator, password="wrong").locked

    result = authenticator.check({"proxy-authorization": "garbage"}, "192.0.2.10")

    assert result.reason == "locked"
    assert result.locked


def test_lockout_expiry_allows_attempt_and_requires_new_threshold():
    clock = FakeClock()
    authenticator = Authenticator(
        config(max_failures=2, lockout_seconds=60), clock=clock
    )
    result_for(authenticator, password="wrong")
    result_for(authenticator, password="wrong")
    clock.advance(61)

    after_expiry = result_for(authenticator, password="wrong")

    assert after_expiry.reason == "bad_creds"
    assert not after_expiry.locked


def test_failure_window_prunes_old_failures():
    clock = FakeClock()
    authenticator = Authenticator(
        config(max_failures=2, failure_window_seconds=10), clock=clock
    )
    result_for(authenticator, password="wrong")
    clock.advance(11)

    result = result_for(authenticator, password="wrong")

    assert result.reason == "bad_creds"
    assert not result.locked


def test_lockout_isolated_per_client_ip():
    authenticator = Authenticator(config(max_failures=1))
    result_for(authenticator, password="wrong")

    other_ip = authenticator.check(
        auth_header(password="wrong"), "192.0.2.11"
    )

    assert other_ip.reason == "bad_creds"
    assert not other_ip.locked


def test_lockout_retry_after_is_rounded_up():
    clock = FakeClock()
    authenticator = Authenticator(config(max_failures=1), clock=clock)
    result_for(authenticator, password="wrong")
    clock.advance(0.1)

    result = authenticator.check({}, "192.0.2.10")

    assert result.retry_after == 60


def test_recent_failures_are_newest_last_bounded_and_copied():
    authenticator = Authenticator(config(max_failures=100))
    for _ in range(3):
        result_for(authenticator, password="wrong")

    records = authenticator.recent_failures(2)
    records[0]["reason"] = "changed"

    assert len(records) == 2
    assert records[0]["reason"] == "changed"
    assert authenticator.recent_failures(2)[0]["reason"] == "bad_creds"
    assert authenticator.recent_failures(0) == []
    assert authenticator.recent_failures("invalid") == []


def test_history_timestamps_are_utc_iso8601_and_no_password_is_present():
    password = "do-not-leak"
    authenticator = Authenticator(config())
    result_for(authenticator, password=password)

    record = authenticator.recent_failures()[0]

    assert re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z",
        record["ts"],
    )
    assert password not in repr(record)


def test_failure_client_tracking_is_bounded(monkeypatch):
    authenticator = Authenticator(config(max_failures=100))
    monkeypatch.setattr("proxy.control.auth._MAX_TRACKED_CLIENTS", 2)

    authenticator._failed("ip-1", "user", "bad_creds", 1.0)
    authenticator._failed("ip-2", "user", "bad_creds", 1.0)
    authenticator._failed("ip-3", "user", "bad_creds", 1.0)

    assert list(authenticator._failures) == ["ip-2", "ip-3"]


def test_reload_callback_reloads_settings_and_clears_cache():
    class ReloadableConfig(DictConfig):
        def add_reload_listener(self, callback):
            self.callback = callback

    cfg = ReloadableConfig(config()._d)
    authenticator = Authenticator(cfg)
    result_for(authenticator)
    assert authenticator._cache

    cfg._d["auth"]["enabled"] = False
    cfg.callback()

    assert authenticator.check({}, "ip").ok
    assert authenticator._cache == {}


def test_malformed_user_records_are_rejected_without_raising():
    users = {
        "bad-type": "not-a-dict",
        "bad-hex": {"salt": "not-hex", "hash": "00"},
        "empty": {"salt": "", "hash": ""},
        "missing": {},
    }

    authenticator = Authenticator(config(users=users, max_failures=100))

    for index, username in enumerate(users):
        result = authenticator.check(
            auth_header(username=username),
            f"192.0.2.{20 + index}",
        )
        assert result.reason == "bad_creds"


def test_challenge_response_has_exact_safe_headers():
    authenticator = Authenticator(
        config(realm='my "realm"\\name\r\nignored')
    )

    response = authenticator.challenge_response()

    assert response == (
        b"HTTP/1.1 407 Proxy Authentication Required\r\n"
        b'Proxy-Authenticate: Basic realm="my \\"realm\\"\\\\nameignored"\r\n'
        b"Content-Length: 0\r\n"
        b"Connection: close\r\n\r\n"
    )


@pytest.mark.parametrize(
    "retry_after, expected",
    [
        (5, "5"),
        (0, "0"),
        (-1, "0"),
        (True, "0"),
        ("bad", "0"),
        (None, "0"),
    ],
)
def test_locked_response_sanitizes_retry_after(retry_after, expected):
    response = Authenticator(config()).locked_response(retry_after)

    assert response == (
        f"HTTP/1.1 429 Too Many Requests\r\n"
        f"Retry-After: {expected}\r\n"
        "Content-Length: 0\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii")


def test_build_auth_returns_authenticator():
    authenticator = build_auth(config())

    assert isinstance(authenticator, Authenticator)
