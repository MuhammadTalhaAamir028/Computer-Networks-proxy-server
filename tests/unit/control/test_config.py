import json
import signal

import pytest

from proxy.control import config as config_mod
from proxy.control.config import ConfigError, install_sighup, load_config


def test_defaults_and_defensive_reads():
    cfg = load_config([])
    assert cfg.get("proxy.port") == 8080
    domains = cfg.get("filter.deny_domains")
    domains.append("evil.example")
    assert cfg.get("filter.deny_domains") == []
    snapshot = cfg.as_dict(redact=False)
    snapshot["proxy"]["port"] = 1
    assert cfg.get("proxy.port") == 8080


def test_file_and_cli_overrides(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"proxy": {"port": 9000}}), encoding="utf-8")
    cfg = load_config(["--config", str(path), "--set", "proxy.port=9001"])
    assert cfg.get("proxy.port") == 9001


def test_environment_file_overrides_explicit_file(tmp_path, monkeypatch):
    explicit = tmp_path / "explicit.json"
    environment = tmp_path / "environment.json"
    explicit.write_text('{"proxy": {"port": 9000}}', encoding="utf-8")
    environment.write_text('{"proxy": {"port": 9002}}', encoding="utf-8")
    monkeypatch.setenv("PROXY_CONFIG", str(environment))

    cfg = load_config(["--config", str(explicit)])

    assert cfg.get("proxy.port") == 9002


def test_named_cli_flags_override_environment_file(tmp_path, monkeypatch):
    path = tmp_path / "environment.json"
    path.write_text(
        '{"proxy": {"host": "192.0.2.1", "port": 9000}, '
        '"admin": {"port": 9003}, "logging": {"file": "old.log"}}',
        encoding="utf-8",
    )
    monkeypatch.setenv("PROXY_CONFIG", str(path))

    cfg = load_config([
        "--host", "127.0.0.2", "--port", "9001",
        "--admin-port", "9004", "--log-file", "new.log",
    ])

    assert cfg.get("proxy.host") == "127.0.0.2"
    assert cfg.get("proxy.port") == 9001
    assert cfg.get("admin.port") == 9004
    assert cfg.get("logging.file") == "new.log"


@pytest.mark.parametrize(
    "key,value",
    [
        ("proxy.connect_timeout", "NaN"),
        ("proxy.read_timeout", "-1"),
        ("filter.blocked_ports", "[true]"),
        ("filter.private_allow", '["127.0.0.1"]'),
        ("filter.deny_domains", '["*."]'),
        ("filter.deny_url_regex", '["["]'),
        ("admin.port", "70000"),
    ],
)
def test_schema_rejects_invalid_values(tmp_path, key, value):
    path = tmp_path / "bad.json"
    section, leaf = key.split(".", 1)
    path.write_text(json.dumps({section: {leaf: json.loads(value)}}),
                    encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(["--config", str(path)])


def test_auth_diagnostics_do_not_leak_nested_secrets(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text(json.dumps({
        "auth": {"users": {"alice": {"salt": "not hex", "hash": 123}}},
    }), encoding="utf-8")
    with pytest.raises(ConfigError) as exc:
        load_config(["--config", str(path)])
    message = str(exc.value)
    assert "not hex" not in message
    assert "123" not in message
    assert "alice.salt" in message


def test_multiple_validation_errors_are_reported_without_secret_values(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text(json.dumps({
        "proxy": {"port": 0, "connect_timeout": -1},
        "filter": {"blocked_ports": [0, 70000]},
        "auth": {"users": {"alice": {"salt": "secret-salt", "hash": "secret-hash"}}},
    }), encoding="utf-8")

    with pytest.raises(ConfigError) as exc:
        load_config(["--config", str(path)])

    message = str(exc.value)
    assert "proxy.port" in message
    assert "proxy.connect_timeout" in message
    assert "filter.blocked_ports[0]" in message
    assert "filter.blocked_ports[1]" in message
    assert "secret-salt" not in message
    assert "secret-hash" not in message


def test_unknown_cli_option_and_malformed_set_are_rejected():
    with pytest.raises(ConfigError):
        load_config(["--not-a-real-option"])
    with pytest.raises(ConfigError):
        load_config(["--set", "proxy.port"])


def test_unknown_set_key_is_warned_not_rejected(caplog):
    with caplog.at_level("WARNING", logger=config_mod._log.name):
        cfg = load_config(["--set", "future.option=1"])
    assert cfg.get("future.option") == 1
    assert "Unknown configuration key: future.option" in caplog.text


def test_reload_failure_preserves_snapshot_and_success_notifies(tmp_path):
    path = tmp_path / "config.json"
    path.write_text('{"proxy": {"port": 9000}}', encoding="utf-8")
    cfg = load_config(["--config", str(path)])
    calls = []
    cfg.add_reload_listener(lambda current: calls.append(current.get("proxy.port")))
    path.write_text('{"proxy": {"port": 0}}', encoding="utf-8")
    assert not cfg.reload()
    assert cfg.get("proxy.port") == 9000
    assert calls == []
    path.write_text('{"proxy": {"port": 9001}}', encoding="utf-8")
    assert cfg.reload()
    assert cfg.get("proxy.port") == 9001
    assert calls == [9001]


def test_reload_listener_failure_is_logged_but_snapshot_stays_valid(
    tmp_path, caplog
):
    path = tmp_path / "config.json"
    path.write_text('{"proxy": {"port": 9001}}', encoding="utf-8")
    cfg = load_config(["--config", str(path)])

    def broken_listener(_current):
        raise RuntimeError("listener failed")

    cfg.add_reload_listener(broken_listener)
    with caplog.at_level("ERROR", logger=config_mod._log.name):
        assert cfg.reload()

    assert cfg.get("proxy.port") == 9001
    assert "Reload listener" in caplog.text


def test_sighup_installation_is_safe(monkeypatch):
    monkeypatch.setattr(signal, "signal", lambda *args: (_ for _ in ()).throw(
        ValueError("not main thread")
    ))
    assert install_sighup(load_config([])) is False


def test_sighup_returns_false_when_signal_is_unavailable(monkeypatch):
    monkeypatch.delattr(signal, "SIGHUP", raising=False)
    assert install_sighup(load_config([])) is False


def test_redaction_hides_nested_credentials():
    cfg = load_config([])
    with pytest.raises(TypeError):
        cfg._snapshot["auth"] = {}
    cfg = config_mod.Config({
        **config_mod._DEFAULTS,
        "auth": {
            **config_mod._DEFAULTS["auth"],
            "users": {
                "alice": {"salt": "aa", "hash": "bb", "note": "ok"}
            },
        },
    })
    result = cfg.as_dict()
    assert result["auth"]["users"]["alice"]["salt"] == "[REDACTED]"
    assert result["auth"]["users"]["alice"]["hash"] == "[REDACTED]"
    assert result["auth"]["users"]["alice"]["note"] == "ok"


def test_file_errors_are_config_errors(tmp_path):
    with pytest.raises(ConfigError, match="not found"):
        load_config(["--config", str(tmp_path / "missing.json")])

    directory = tmp_path / "directory"
    directory.mkdir()
    with pytest.raises(ConfigError, match="directory"):
        load_config(["--config", str(directory)])


def test_get_returns_defensive_nested_credential_copy():
    cfg = config_mod.Config({
        "auth": {"users": {"alice": {"salt": "aa", "hash": "bb"}}}
    })
    users = cfg.get("auth.users")
    users["alice"]["hash"] = "changed"

    assert cfg.get("auth.users.alice.hash") == "bb"
