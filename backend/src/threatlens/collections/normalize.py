"""Deterministic indicator-value normalization for deduplication.

An indicator's identity is ``(type, normalized_value)`` — never the raw,
analyst-typed string (see
:class:`~threatlens.collections.models.Indicator`). Two indicators of the
same type that normalize to the same value are the same indicator.

Every normalizer here is a pure string transform: no network, no
validation-as-rejection. A value that doesn't parse under its type's
canonical form (e.g. a malformed IP) falls back to a simple case-fold rather
than raising — Collections store whatever intelligence the analyst
explicitly provides ("Collections store only explicitly provided
intelligence", per the phase brief's Determinism section); rejecting
malformed input is the Search engine's job, not this one's.
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit, urlunsplit

from .models import IndicatorType

# Types whose published canonical form is uppercase (CVE-2024-3094,
# T1059.001, S0154, G0016). Every other type is compared case-insensitively
# in lowercase — the more common convention for hostnames, hashes, paths, etc.
_UPPERCASE_TYPES = frozenset(
    {
        IndicatorType.CVE,
        IndicatorType.MITRE_TECHNIQUE,
        IndicatorType.MITRE_SOFTWARE,
        IndicatorType.MITRE_GROUP,
    }
)


def normalize_indicator_value(indicator_type: IndicatorType, value: str) -> str:
    """The canonical form of ``value`` for ``indicator_type``, used as dedup identity."""
    stripped = value.strip()
    if indicator_type in (IndicatorType.IPV4, IndicatorType.IPV6):
        try:
            return ipaddress.ip_address(stripped).compressed
        except ValueError:
            return stripped.lower()
    if indicator_type == IndicatorType.URL:
        return _normalize_url(stripped)
    if indicator_type in _UPPERCASE_TYPES:
        return stripped.upper()
    return stripped.lower()


def _normalize_url(value: str) -> str:
    """Lowercase the scheme and host; leave path/query/fragment casing intact
    (paths are case-sensitive per RFC 3986, unlike scheme/host)."""
    try:
        parts = urlsplit(value)
    except ValueError:
        return value.lower()
    return urlunsplit(
        (parts.scheme.lower(), parts.netloc.lower(), parts.path, parts.query, parts.fragment)
    )
