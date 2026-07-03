"""Enumerations for the Detection Knowledge Library (Phase 4.6).

Closed, typed vocabularies for the *community* detection library — a strictly
downstream, read-only consumer that discovers, normalizes, indexes, and
recommends existing community detection content. It reuses the frozen Detection
Engine's language / severity / category vocabularies (community rules are
written in the same languages ThreatLens generates) and never touches them.

Nothing here generates detections; the library only describes and compares
content authored elsewhere.
"""

from __future__ import annotations

from enum import StrEnum

# Re-exported so consumers import one vocabulary; these are the frozen Detection
# Engine enums, reused verbatim (community rules use the same languages).
from ..detection.types import DetectionCategory, DetectionLanguage, DetectionSeverity

__all__ = [
    "DetectionCategory",
    "DetectionLanguage",
    "DetectionSeverity",
    "LicenseSupport",
    "RuleMatchType",
    "RulePlatform",
    "SyncStatus",
]


class RuleMatchType(StrEnum):
    """How a community rule relates to an investigation (deterministic).

    Ordered by strength: an ``EXACT`` match shares a concrete indicator with the
    investigation; ``PARTIAL`` shares behaviour (technique / malware / actor);
    ``RELATED`` shares only theme (category / tag / platform); ``NONE`` is below
    the recommendation floor and never surfaced.
    """

    EXACT = "exact"
    PARTIAL = "partial"
    RELATED = "related"
    NONE = "none"


class RulePlatform(StrEnum):
    """The telemetry surface a community rule targets (normalized, closed set)."""

    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"
    NETWORK = "network"
    CLOUD = "cloud"
    WEB = "web"
    CONTAINER = "container"
    GENERIC = "generic"


class LicenseSupport(StrEnum):
    """Whether the library may redistribute a rule's *content* under its license.

    ``PERMISSIVE`` / ``COPYLEFT`` licenses allow display and download with
    attribution preserved. ``RESTRICTED`` allows metadata + attribution but the
    content is shown only with its notice. ``UNSUPPORTED`` withholds content
    (metadata + link only); ``UNKNOWN`` is treated conservatively as restricted.
    """

    PERMISSIVE = "permissive"
    COPYLEFT = "copyleft"
    RESTRICTED = "restricted"
    UNSUPPORTED = "unsupported"
    UNKNOWN = "unknown"


class SyncStatus(StrEnum):
    """Freshness of the local library relative to its upstream sources."""

    SEED = "seed"  # serving the bundled offline seed corpus (never synced)
    SYNCED = "synced"  # a sync has populated the cache
    STALE = "stale"  # cache exists but is older than the configured TTL
    ERROR = "error"  # last sync attempt failed; serving the previous cache/seed
