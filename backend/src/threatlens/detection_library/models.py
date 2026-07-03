"""Canonical models for the Detection Knowledge Library (Phase 4.6).

Every community provider normalizes its idiosyncratic repository content into
these frozen, deterministic models. They are the library's contract, kept
completely separate from the Detection Engine's ``DetectionPackage`` /
``DetectionArtifact`` so a *generated* detection can never be confused with a
*community* detection — provenance is explicit and never merged.

The models are pure data: no I/O, no network, no clock. Identity
(``CommunityRule.id``) is content-addressed so the same upstream rule always maps
to the same id regardless of when it was synced.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from ..entities.types import EntityType
from .types import (
    DetectionCategory,
    DetectionLanguage,
    DetectionSeverity,
    LicenseSupport,
    RuleMatchType,
    RulePlatform,
    SyncStatus,
)

# --------------------------------------------------------------------------- #
# Provenance (repository · author · license · version · references)
# --------------------------------------------------------------------------- #


class RuleLicense(BaseModel):
    """A rule's license, preserved verbatim from its repository.

    Attribution is never removed and content is never relicensed; ``support``
    only governs whether the library may redistribute the rule *body* (see
    :class:`LicenseSupport`).
    """

    model_config = ConfigDict(frozen=True)

    spdx_id: str = Field(min_length=1)  # e.g. "DRL-1.1", "Apache-2.0", "Elastic-2.0"
    name: str = Field(min_length=1)
    support: LicenseSupport
    url: str | None = None
    note: str = ""

    @property
    def redistributable(self) -> bool:
        """True if the rule body may be displayed/downloaded (attribution kept)."""
        return self.support in (LicenseSupport.PERMISSIVE, LicenseSupport.COPYLEFT)


class RuleAuthor(BaseModel):
    """Attribution for a community rule. Never dropped or rewritten."""

    model_config = ConfigDict(frozen=True)

    name: str = Field(min_length=1)
    url: str | None = None
    organization: str | None = None


class RuleReference(BaseModel):
    """An external reference cited by a community rule (mirrors DetectionReference)."""

    model_config = ConfigDict(frozen=True)

    title: str = Field(min_length=1)
    url: str


class RuleVersion(BaseModel):
    """Version / revision tracking for a community rule.

    ``content_hash`` is the stable fingerprint used for incremental sync and
    change detection: a differing hash means the upstream rule changed.
    """

    model_config = ConfigDict(frozen=True)

    version: str = "1"
    revision: int = Field(default=1, ge=1)
    content_hash: str = Field(min_length=1)
    updated: str | None = None  # ISO date string as published upstream (never invented)


class RuleSource(BaseModel):
    """A community detection *repository* the library federates over.

    Read-only provenance: the library fetches and normalizes from these but never
    writes back. Adding a source is data (a descriptor), not a framework change.
    """

    model_config = ConfigDict(frozen=True)

    id: str = Field(min_length=1)  # machine id, e.g. "sigmahq"
    name: str = Field(min_length=1)  # display name
    repository: str = Field(min_length=1)  # "org/repo"
    url: str  # repository URL
    license: RuleLicense
    priority: int = Field(default=100, ge=0)  # lower ranks first in recommendations
    languages: tuple[DetectionLanguage, ...] = ()
    description: str = ""


# --------------------------------------------------------------------------- #
# Extracted signals (MITRE · IOC mappings)
# --------------------------------------------------------------------------- #


class RuleIOC(BaseModel):
    """A concrete indicator extracted deterministically from a rule's content."""

    model_config = ConfigDict(frozen=True)

    type: EntityType
    value: str = Field(min_length=1)


# --------------------------------------------------------------------------- #
# The canonical community rule
# --------------------------------------------------------------------------- #


class CommunityRule(BaseModel):
    """One normalized community detection rule — the library's atom.

    Self-describing: it embeds its source, author, license, and version so a
    single rule carries full provenance wherever it is displayed. The raw
    ``content`` is preserved verbatim (never rewritten); it is withheld
    (``content is None``) only when the license does not permit redistribution,
    in which case metadata + ``url`` still stand.
    """

    model_config = ConfigDict(frozen=True)

    id: str = Field(min_length=1)  # content-addressed, e.g. "com_ab12cd34ef56gh78"
    source: RuleSource
    rule_id: str = Field(min_length=1)  # the upstream id (Sigma UUID, YARA name, sid…)
    name: str = Field(min_length=1)
    language: DetectionLanguage
    category: DetectionCategory = DetectionCategory.GENERIC
    severity: DetectionSeverity = DetectionSeverity.MEDIUM
    description: str = ""
    author: RuleAuthor
    license: RuleLicense
    version: RuleVersion
    url: str  # the rule's canonical URL in its repository
    path: str = ""  # path within the repository
    tags: tuple[str, ...] = ()
    mitre_techniques: tuple[str, ...] = ()
    threat_actors: tuple[str, ...] = ()
    malware_families: tuple[str, ...] = ()
    platforms: tuple[RulePlatform, ...] = ()
    iocs: tuple[RuleIOC, ...] = ()
    references: tuple[RuleReference, ...] = ()
    content: str | None = None  # verbatim rule text, or None when not redistributable


# --------------------------------------------------------------------------- #
# Matching a rule to an investigation
# --------------------------------------------------------------------------- #


class RuleMatch(BaseModel):
    """A community rule scored against one investigation (deterministic).

    ``similarity`` and ``coverage`` are pure 0–100 integers; the ``shared_*``
    lists make the score explainable, and the rule is embedded so the match is a
    complete, self-contained recommendation.
    """

    model_config = ConfigDict(frozen=True)

    rule: CommunityRule
    match_type: RuleMatchType
    similarity: int = Field(ge=0, le=100)
    coverage: int = Field(ge=0, le=100)
    shared_iocs: tuple[str, ...] = ()
    shared_techniques: tuple[str, ...] = ()
    shared_malware: tuple[str, ...] = ()
    shared_actors: tuple[str, ...] = ()
    rationale: str = ""


# --------------------------------------------------------------------------- #
# Top-level outputs (recommendation · search · library stats)
# --------------------------------------------------------------------------- #


class LibraryStats(BaseModel):
    """A snapshot of what the indexed library currently holds."""

    model_config = ConfigDict(frozen=True)

    total_rules: int = Field(ge=0)
    sources: int = Field(ge=0)
    sync_status: SyncStatus = SyncStatus.SEED
    by_language: dict[str, int] = Field(default_factory=dict)
    by_source: dict[str, int] = Field(default_factory=dict)
    library_version: str = "1.0"


class CommunityRecommendation(BaseModel):
    """The Detection Knowledge result for one investigation.

    Strictly separate from a ``DetectionPackage``: these are *community* rules
    that resemble the investigation, never generated content and never merged
    with it. ``generated_at`` is inherited from the summary (the library reads no
    clock), so identical input yields an identical, reproducible result.
    """

    model_config = ConfigDict(frozen=True)

    entity_type: EntityType
    entity_value: str
    matches: tuple[RuleMatch, ...] = ()
    exact_count: int = Field(default=0, ge=0)
    partial_count: int = Field(default=0, ge=0)
    related_count: int = Field(default=0, ge=0)
    library_version: str = "1.0"
    sync_status: SyncStatus = SyncStatus.SEED
    generated_at: datetime | None = None

    @property
    def is_empty(self) -> bool:
        """True when no community rule met the recommendation floor."""
        return not self.matches


class CommunitySearchResult(BaseModel):
    """A page of library search results (deterministic order)."""

    model_config = ConfigDict(frozen=True)

    total: int = Field(ge=0)
    rules: tuple[CommunityRule, ...] = ()
    stats: LibraryStats
