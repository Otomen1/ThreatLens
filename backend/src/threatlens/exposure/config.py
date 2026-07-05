"""Environment-driven configuration for the Exposure Intelligence Framework.

Mirrors ``ai/config.py``'s pattern. Exposure Intelligence is **off by
default** — Phase 5.0 ships no providers, so there is nothing to enable yet;
the settings exist so a later phase's providers configure against a stable
contract without changing callers.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field

_DEFAULT_TIMEOUT = 10.0
_TRUTHY = frozenset({"1", "true", "yes", "on"})


def _truthy(value: str | None) -> bool:
    return value is not None and value.strip().lower() in _TRUTHY


@dataclass(frozen=True)
class ExposureConfig:
    """Resolved Exposure Intelligence configuration (immutable)."""

    enabled: bool = False
    cache_enabled: bool = True
    timeout: float = _DEFAULT_TIMEOUT
    rate_limit_per_minute: int | None = None
    # Per-provider enable/disable overrides, keyed by provider name — future-
    # proofing for Phase 5.1+; empty until real providers exist.
    provider_overrides: dict[str, bool] = field(default_factory=dict)

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> ExposureConfig:
        """Build settings from environment variables (``os.environ`` by default)."""
        source: Mapping[str, str] = os.environ if env is None else env
        try:
            timeout = float(source.get("EXPOSURE_TIMEOUT", "") or _DEFAULT_TIMEOUT)
        except ValueError:
            timeout = _DEFAULT_TIMEOUT
        raw_rate_limit = (source.get("EXPOSURE_RATE_LIMIT_PER_MINUTE", "") or "").strip()
        rate_limit = int(raw_rate_limit) if raw_rate_limit.isdigit() else None
        return cls(
            enabled=_truthy(source.get("EXPOSURE_ENABLED")),
            cache_enabled=_truthy(source.get("EXPOSURE_CACHE_ENABLED"))
            if source.get("EXPOSURE_CACHE_ENABLED") is not None
            else True,
            timeout=timeout,
            rate_limit_per_minute=rate_limit,
        )
