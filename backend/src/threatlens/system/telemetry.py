"""Passive provider HTTP telemetry; never performs an extra request."""

from __future__ import annotations

from collections.abc import Mapping
from contextvars import ContextVar, Token

from .metrics import registry

_provider: ContextVar[str | None] = ContextVar("threatlens_provider", default=None)


def enter_provider(name: str) -> Token[str | None]:
    return _provider.set(name)


def leave_provider(token: Token[str | None]) -> None:
    _provider.reset(token)


def observe_response(status_code: int, headers: Mapping[str, str]) -> None:
    provider = _provider.get()
    if provider:
        registry.record_provider_http(provider, status_code=status_code, headers=dict(headers))
