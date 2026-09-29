import pytest

import proxy.control as control
from proxy.control.auth import Authenticator, build_auth as concrete_build_auth
from proxy.control.filter_engine import (
    FilterEngine,
    build_filter as concrete_build_filter,
)
from proxy.control.config import load_config
from proxy.stubs import DictConfig


def test_public_api_exports_only_frozen_factories():
    assert control.__all__ == ["build_filter", "build_auth"]
    assert control.build_filter is concrete_build_filter
    assert control.build_auth is concrete_build_auth


def test_build_filter_delegates_to_real_filter_engine():
    config = load_config([])

    result = control.build_filter(config)

    assert isinstance(result, FilterEngine)
    assert result.describe()["mode"] == "denylist"


def test_build_auth_delegates_to_real_authenticator():
    config = load_config([])

    result = control.build_auth(config)

    assert isinstance(result, Authenticator)
    assert result.check({}, "192.0.2.1").ok


def test_factory_errors_are_not_replaced_with_security_fallbacks():
    config = DictConfig({"filter": {"mode": "invalid"}})

    with pytest.raises(ValueError):
        control.build_filter(config)
