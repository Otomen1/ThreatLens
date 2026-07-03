"""Detection Knowledge Library (Phase 4.6) — the community-detection subsystem.

A strictly **downstream, read-only** consumer that discovers, normalizes,
indexes, searches, and recommends *existing community detection content*
(SigmaHQ, YARA-Rules, Emerging Threats, Elastic, Microsoft, Talos, Splunk). It
never generates detections and never touches the frozen Detection Engine — a
*generated* detection and a *community* detection are kept explicitly separate,
never merged.

Public entry points:

* :func:`build_default_provider_registry` — the seven default community sources.
* :class:`DetectionLibrary` — an indexed, searchable set of :class:`CommunityRule`.
* :func:`recommend` — deterministically match an ``InvestigationSummary`` to the
  library (exact / partial / related), no AI, no embeddings.
* :class:`DetectionKnowledgeService` — the offline-first API facade.
* :func:`synchronize` — the separate (clock-aware) sync-into-cache step.
"""

from __future__ import annotations

from .config import DetectionLibraryConfig
from .defaults import DEFAULT_SOURCES, build_default_provider_registry
from .library import DetectionLibrary
from .matching import recommend
from .models import (
    CommunityRecommendation,
    CommunityRule,
    CommunitySearchResult,
    LibraryStats,
    RuleAuthor,
    RuleIOC,
    RuleLicense,
    RuleMatch,
    RuleReference,
    RuleSource,
    RuleVersion,
)
from .normalize import normalize_record
from .providers.base import CommunityProvider, CommunityProviderRegistry
from .service import DetectionKnowledgeService
from .similarity import MatchProfile, profile_from_summary, score
from .sync import LibraryCache, SyncDiff, diff, invalidate, synchronize
from .types import (
    DetectionCategory,
    DetectionLanguage,
    DetectionSeverity,
    LicenseSupport,
    RuleMatchType,
    RulePlatform,
    SyncStatus,
)

DETECTION_LIBRARY_VERSION = "1.0"
"""The Detection Knowledge Library contract version (matching / normalization)."""

__all__ = [
    "DEFAULT_SOURCES",
    "DETECTION_LIBRARY_VERSION",
    "CommunityProvider",
    "CommunityProviderRegistry",
    "CommunityRecommendation",
    "CommunityRule",
    "CommunitySearchResult",
    "DetectionCategory",
    "DetectionKnowledgeService",
    "DetectionLanguage",
    "DetectionLibrary",
    "DetectionLibraryConfig",
    "DetectionSeverity",
    "LibraryCache",
    "LibraryStats",
    "LicenseSupport",
    "MatchProfile",
    "RuleAuthor",
    "RuleIOC",
    "RuleLicense",
    "RuleMatch",
    "RuleMatchType",
    "RulePlatform",
    "RuleReference",
    "RuleSource",
    "RuleVersion",
    "SyncDiff",
    "SyncStatus",
    "build_default_provider_registry",
    "diff",
    "invalidate",
    "normalize_record",
    "profile_from_summary",
    "recommend",
    "score",
    "synchronize",
]
