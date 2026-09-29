"""Public control API for the Sufyan rules/security layer.

This package exposes the frozen factory functions expected by the rest of the
project. The concrete implementations live in later phases, while this package
keeps a lightweight compatibility fallback for solo execution before those files
exist.
"""

from __future__ import annotations

from importlib import import_module
from typing import Any

from proxy.interfaces import Auth, Config, FilterEngine
from proxy.stubs import AllowAllFilter, NoAuth

__all__ = ["build_filter", "build_auth"]


def build_filter(config: Config) -> FilterEngine:
    """Build and return the configured rules/filter engine."""
    try:
        module = import_module(".filter_engine", __name__)
    except ModuleNotFoundError:
        return AllowAllFilter()

    factory = getattr(module, "build_filter", None)
    if callable(factory):
        return factory(config)
    return AllowAllFilter()


def build_auth(config: Config) -> Auth:
    """Build and return the configured proxy authentication object."""
    try:
        module = import_module(".auth", __name__)
    except ModuleNotFoundError:
        return NoAuth()

    factory = getattr(module, "build_auth", None)
    if callable(factory):
        return factory(config)
    return NoAuth()
