"""Small shared helpers for normalizing provider payloads.

Generic field extraction reused by multiple providers (e.g. MalwareBazaar and
URLhaus, which both return abuse.ch JSON). Provider-specific mapping — which
field becomes which Evidence/Relationship — stays in each provider; only these
primitives are shared, so networking and parsing logic is never duplicated.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any

# abuse.ch timestamps, e.g. "2024-01-02 03:04:05" (sometimes suffixed " UTC").
DATETIME_FORMATS: tuple[str, ...] = ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S UTC")


def opt_str(data: Mapping[str, Any], key: str) -> str | None:
    """Return ``data[key]`` as a stripped non-empty string, or ``None``."""
    value = data.get(key)
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def str_list(data: Mapping[str, Any], key: str) -> list[str]:
    """Return ``data[key]`` as a list of stripped non-empty strings."""
    raw = data.get(key)
    if not isinstance(raw, list):
        return []
    return [str(item).strip() for item in raw if str(item).strip()]


def parse_datetime(
    value: str | None, formats: Sequence[str] = DATETIME_FORMATS
) -> datetime | None:
    """Parse ``value`` against ``formats`` (UTC), or ``None`` if it doesn't match."""
    if not value:
        return None
    for fmt in formats:
        try:
            return datetime.strptime(value, fmt).replace(tzinfo=UTC)
        except ValueError:
            continue
    return None


def parse_iso_datetime(value: str | None) -> datetime | None:
    """Parse an ISO-8601 timestamp (e.g. AbuseIPDB's ``lastReportedAt``)."""
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None
