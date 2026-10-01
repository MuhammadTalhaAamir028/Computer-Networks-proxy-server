import base64
import io
import json
from contextlib import redirect_stderr

from proxy.control.auth import Authenticator
from proxy.control.mkuser import main
from proxy.stubs import DictConfig


def _run(name, passwords):
    output = io.StringIO()
    errors = io.StringIO()
    prompts = iter(passwords)

    def prompt(_message):
        return next(prompts)

    with redirect_stderr(errors):
        code = main([name], prompt=prompt, out=output)
    return code, output.getvalue(), errors.getvalue()


def _parse_entry(output):
    return json.loads("{" + output.strip() + "}")


def _auth_for(entry):
    return Authenticator(
        DictConfig({"auth": {"enabled": True, "users": entry}})
    )


def _header(username, password):
    token = base64.b64encode(f"{username}:{password}".encode("utf-8"))
    return {"proxy-authorization": "Basic " + token.decode("ascii")}


def test_output_parses_as_json_when_wrapped():
    code, output, errors = _run("alice", ["pw", "pw"])

    assert code == 0
    assert errors == ""
    assert list(_parse_entry(output)) == ["alice"]


def test_salt_and_hash_have_required_hex_lengths():
    _, output, _ = _run("alice", ["pw", "pw"])
    credentials = _parse_entry(output)["alice"]

    assert len(credentials["salt"]) == 32
    assert len(credentials["hash"]) == 64
    int(credentials["salt"], 16)
    int(credentials["hash"], 16)


def test_round_trip_authentication_accepts_password():
    password = "密码"
    _, output, _ = _run("alice", [password, password])
    entry = _parse_entry(output)

    result = _auth_for(entry).check(_header("alice", password), "127.0.0.1")

    assert result.ok
    assert result.user == "alice"


def test_wrong_password_is_rejected():
    _, output, _ = _run("alice", ["correct", "correct"])

    result = _auth_for(_parse_entry(output)).check(
        _header("alice", "wrong"), "127.0.0.1"
    )

    assert not result.ok


def test_two_runs_have_different_salts():
    _, first, _ = _run("alice", ["pw", "pw"])
    _, second, _ = _run("alice", ["pw", "pw"])

    assert _parse_entry(first)["alice"]["salt"] != _parse_entry(second)["alice"]["salt"]


def test_colon_username_returns_exit_two_without_stdout():
    code, output, _ = _run("a:b", ["pw", "pw"])

    assert code == 2
    assert output == ""


def test_mismatched_repeat_returns_exit_two_without_stdout():
    code, output, _ = _run("alice", ["one", "two"])

    assert code == 2
    assert output == ""


def test_password_never_appears_in_output_or_errors():
    password = "Never-print-this-密码"
    code, output, errors = _run("alice", [password, "different"])

    assert code == 2
    assert password not in output
    assert password not in errors
