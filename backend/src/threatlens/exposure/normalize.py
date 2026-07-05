"""Small shared helpers for normalizing exposure-provider payloads.

Mirrors ``providers/_normalize.py``: generic field extraction any future
provider can reuse. Provider-specific mapping — which raw field becomes which
``ExposureEvidence``/``ExposureAsset`` — stays in each provider; only these
primitives are shared, so parsing logic is never duplicated across providers.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime


def opt_str(data: Mapping[str, object], key: str) -> str | None:
    """Return ``data[key]`` as a stripped non-empty string, or ``None``."""
    value = data.get(key)
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def str_list(data: Mapping[str, object], key: str) -> list[str]:
    """Return ``data[key]`` as a list of stripped non-empty strings."""
    raw = data.get(key)
    if not isinstance(raw, list):
        return []
    return [str(item).strip() for item in raw if str(item).strip()]


def parse_iso_datetime(value: str | None) -> datetime | None:
    """Parse an ISO-8601 timestamp, or ``None`` if absent/unparseable."""
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None
