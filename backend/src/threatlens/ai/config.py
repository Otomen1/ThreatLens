"""Environment-driven configuration for the AI explanation layer.

AI is **off by default** — ThreatLens must behave identically with or without an
AI provider, so an absent/disabled configuration simply yields a "disabled"
explanation. The model and endpoint are configurable; nothing is hardcoded.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass

_DEFAULT_OLLAMA_URL = "http://localhost:11434"
_DEFAULT_OLLAMA_MODEL = "qwen3:8b"
_DEFAULT_PROVIDER = "ollama"
_DEFAULT_TIMEOUT = 60.0
_TRUTHY = frozenset({"1", "true", "yes", "on"})


def _truthy(value: str | None) -> bool:
    return value is not None and value.strip().lower() in _TRUTHY


def _clean(value: str | None, default: str) -> str:
    """A stripped value, falling back to ``default`` when blank/missing."""
    if value is None:
        return default
    stripped = value.strip()
    return stripped or default


@dataclass(frozen=True)
class AISettings:
    """Resolved AI configuration (immutable)."""

    enabled: bool = False
    provider: str = _DEFAULT_PROVIDER
    ollama_url: str = _DEFAULT_OLLAMA_URL
    ollama_model: str = _DEFAULT_OLLAMA_MODEL
    timeout: float = _DEFAULT_TIMEOUT

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> AISettings:
        """Build settings from environment variables (``os.environ`` by default)."""
        source: Mapping[str, str] = os.environ if env is None else env
        try:
            timeout = float(source.get("AI_TIMEOUT", "") or _DEFAULT_TIMEOUT)
        except ValueError:
            timeout = _DEFAULT_TIMEOUT
        return cls(
            enabled=_truthy(source.get("AI_ENABLED")),
            provider=_clean(source.get("AI_PROVIDER"), _DEFAULT_PROVIDER).lower(),
            ollama_url=_clean(source.get("OLLAMA_URL"), _DEFAULT_OLLAMA_URL),
            ollama_model=_clean(source.get("OLLAMA_MODEL"), _DEFAULT_OLLAMA_MODEL),
            timeout=timeout,
        )
