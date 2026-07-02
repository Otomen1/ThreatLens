"""Environment-driven configuration for the Detection Engineering Framework.

Deliberately minimal: the framework is deterministic and offline, so there is
nothing to authenticate or reach. ``DetectionSettings`` is a configuration seam
for later phases — chiefly *which* generators/languages are enabled — resolved
once from the environment. In this phase no languages are enabled by default,
matching the empty generator registry.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field

from .types import DetectionLanguage

_TRUTHY = frozenset({"1", "true", "yes", "on"})
_FALSY = frozenset({"0", "false", "no", "off"})


def _bool(value: str | None, *, default: bool) -> bool:
    if value is None:
        return default
    token = value.strip().lower()
    if token in _TRUTHY:
        return True
    if token in _FALSY:
        return False
    return default


def _parse_languages(raw: str | None) -> frozenset[DetectionLanguage]:
    """Parse a comma-separated language list, ignoring blanks and unknowns."""
    if not raw:
        return frozenset()
    known = {lang.value: lang for lang in DetectionLanguage}
    return frozenset(
        known[token] for part in raw.split(",") if (token := part.strip().lower()) in known
    )


@dataclass(frozen=True)
class DetectionSettings:
    """Resolved detection configuration (immutable)."""

    enabled: bool = True
    languages: frozenset[DetectionLanguage] = field(default_factory=frozenset)

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> DetectionSettings:
        """Build settings from environment variables (``os.environ`` by default).

        * ``DETECTION_ENABLED`` — master switch (default ``true``).
        * ``DETECTION_LANGUAGES`` — comma-separated languages to enable when
          generators exist (default: none).
        """
        source: Mapping[str, str] = os.environ if env is None else env
        return cls(
            enabled=_bool(source.get("DETECTION_ENABLED"), default=True),
            languages=_parse_languages(source.get("DETECTION_LANGUAGES")),
        )
