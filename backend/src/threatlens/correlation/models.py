"""Canonical models for the Investigation Correlation Engine (Phase 7.0).

The Correlation Engine is a **pure, deterministic** consumer of a completed
:class:`~threatlens.reasoning.models.InvestigationSummary`. It combines
*existing* findings into higher-level correlation observations — it never
invents evidence, never scores, and never produces confidence, severity, or
recommendations (those remain the Reasoning Engine's responsibility). Every
observation references the source finding ids it was derived from, so every
correlation is fully explainable.

These are frozen value objects plus closed vocabularies, mirroring the
Detection Engine (``detection/models.py`` + ``detection/types.py``) and the
Exposure/Identity frameworks. No provider-specific fields, no probabilistic
inference, no hidden state.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from ..entities.types import EntityType
from ..reasoning.models import FindingCategory

# --------------------------------------------------------------------------- #
# Vocabularies (closed)
# --------------------------------------------------------------------------- #


class CorrelationCategory(StrEnum):
    """The kind of higher-level observation a correlation rule produces.

    A closed vocabulary. Phase 7.0 gave each of its 12 seed rules its own
    category value 1:1. Phase 7.1 (rule library expansion) instead groups
    rules that represent the *same kind* of higher-level pattern under one
    shared category — e.g. every "+contested" disposition rule across every
    domain emits ``FINDING_CONTESTED`` — so the vocabulary grows by kind of
    pattern, not by rule count. Still describes the *combination* two or more
    findings jointly represent, never a new verdict.
    """

    MALICIOUS_EXPOSED_INFRASTRUCTURE = "malicious_exposed_infrastructure"
    VULNERABLE_EXPOSED_SERVICE = "vulnerable_exposed_service"
    KNOWN_EXPLOITED_VULNERABILITY = "known_exploited_vulnerability"
    KNOWN_EXPLOITED_EXPOSURE = "known_exploited_exposure"
    REPUTATION_CONFIRMED_INFRASTRUCTURE = "reputation_confirmed_infrastructure"
    MISCONFIGURED_EXPOSED_SERVICE = "misconfigured_exposed_service"
    VULNERABILITY_WEAKNESS_LINK = "vulnerability_weakness_link"
    MALWARE_TECHNIQUE_ASSOCIATION = "malware_technique_association"
    ACTOR_TECHNIQUE_MAPPING = "actor_technique_mapping"
    ACTOR_MALWARE_ASSOCIATION = "actor_malware_association"
    CAMPAIGN_INFRASTRUCTURE = "campaign_infrastructure"
    MALWARE_INFRASTRUCTURE_ASSOCIATION = "malware_infrastructure_association"

    # --- Phase 7.1: rule library expansion (additive; nothing above changed) ---

    # Cross-cutting disposition patterns (any domain category + a disposition
    # tag from FindingCategory) — shared across every rules/*.py module.
    FINDING_CONTESTED = "finding_contested"
    FINDING_REQUIRES_ACTION = "finding_requires_action"
    FINDING_LOW_ACTIONABILITY = "finding_low_actionability"
    CORROBORATED_REPUTATION_SIGNAL = "corroborated_reputation_signal"

    # rules/infrastructure.py + rules/vulnerability.py
    MALICIOUS_INFRASTRUCTURE_WEAKNESS_LINK = "malicious_infrastructure_weakness_link"
    MISCONFIGURATION_WEAKNESS_LINK = "misconfiguration_weakness_link"

    # rules/malware.py
    MALWARE_ASSET_ASSOCIATION = "malware_asset_association"
    MALWARE_TECHNIQUE_COLOCATED = "malware_technique_colocated"
    MALWARE_INFRASTRUCTURE_COLOCATED = "malware_infrastructure_colocated"
    MALWARE_CAMPAIGN_LINK = "malware_campaign_link"

    # rules/threat_actor.py
    ACTOR_TECHNIQUE_COLOCATED = "actor_technique_colocated"
    ACTOR_MALWARE_COLOCATED = "actor_malware_colocated"
    ACTOR_INFRASTRUCTURE_LINK = "actor_infrastructure_link"
    ACTOR_CAMPAIGN_LINK = "actor_campaign_link"
    ACTOR_ASSET_ASSOCIATION = "actor_asset_association"

    # rules/campaign.py
    CAMPAIGN_INFRASTRUCTURE_COLOCATED = "campaign_infrastructure_colocated"
    CAMPAIGN_TECHNIQUE_LINK = "campaign_technique_link"
    CAMPAIGN_ASSET_ASSOCIATION = "campaign_asset_association"

    # rules/mitre.py
    TECHNIQUE_INFRASTRUCTURE_LINK = "technique_infrastructure_link"
    TECHNIQUE_VULNERABILITY_LINK = "technique_vulnerability_link"

    # rules/compound.py (three-signal escalations — strictly more specific
    # than any one of their two-category subset rules)
    MULTI_SIGNAL_MALICIOUS_EXPOSURE = "multi_signal_malicious_exposure"
    MULTI_SIGNAL_VULNERABLE_EXPOSURE = "multi_signal_vulnerable_exposure"
    CORROBORATED_MALICIOUS_EXPOSURE = "corroborated_malicious_exposure"
    MULTI_SIGNAL_MISCONFIGURED_VULNERABLE = "multi_signal_misconfigured_vulnerable"
    ACTOR_MALWARE_TECHNIQUE_CONVERGENCE = "actor_malware_technique_convergence"
    CAMPAIGN_ACTOR_INFRASTRUCTURE_CONVERGENCE = "campaign_actor_infrastructure_convergence"


class CorrelationRelationshipType(StrEnum):
    """How two source findings relate within a correlation observation."""

    CO_OCCURS_WITH = "co_occurs_with"
    EXPOSES = "exposes"
    ASSOCIATED_WITH = "associated_with"
    MAPPED_TO = "mapped_to"
    ATTRIBUTED_TO = "attributed_to"
    EXPLOITS = "exploits"


# --------------------------------------------------------------------------- #
# Rule (declarative — the executable data a rule is)
# --------------------------------------------------------------------------- #


class CorrelationRule(BaseModel):
    """A single deterministic correlation rule (declarative data, not code).

    A rule fires when the investigation's findings jointly cover **all** of
    ``required_categories``. With ``same_subject`` the matching findings must
    share one subject (e.g. malicious + exposed on the same IP); otherwise they
    need only co-occur anywhere in the investigation (e.g. a malware finding
    and an ATT&CK-technique finding on different subjects). The engine's single
    generic evaluator interprets this data — there is no per-rule code, so
    every rule is trivially explainable and deterministic.
    """

    model_config = ConfigDict(frozen=True)

    id: str = Field(min_length=1)  # machine id, e.g. "malicious_exposed_infrastructure"
    name: str = Field(min_length=1)  # human label
    description: str = Field(min_length=1)
    category: CorrelationCategory  # the observation category this rule emits
    required_categories: frozenset[FindingCategory] = Field(min_length=2)
    relationship: CorrelationRelationshipType
    title: str = Field(min_length=1)  # the observation title this rule emits
    same_subject: bool = True
    priority: int = 100  # lower runs first; ties break on id


# --------------------------------------------------------------------------- #
# Observation components (all references to existing evidence — never new)
# --------------------------------------------------------------------------- #


class CorrelationEvidence(BaseModel):
    """A reference to one source finding that contributed to a correlation.

    Never new evidence — a pointer back to a :class:`~threatlens.reasoning.models.Finding`
    (by its stable id) plus the category that matched and a copied, descriptive
    summary for readability.
    """

    model_config = ConfigDict(frozen=True)

    finding_id: str = Field(min_length=1)
    matched_category: FindingCategory
    subject_type: EntityType
    subject_value: str = Field(min_length=1)
    summary: str = ""


class CorrelationRelationship(BaseModel):
    """A typed link between two source findings inside a correlation observation."""

    model_config = ConfigDict(frozen=True)

    type: CorrelationRelationshipType
    source_finding_id: str = Field(min_length=1)
    target_finding_id: str = Field(min_length=1)
    description: str = ""


class CorrelationObservation(BaseModel):
    """One higher-level, deterministic observation combining existing findings.

    Content-addressed: its ``id`` hashes the rule, category, subject, and the
    sorted source finding ids — never a timestamp — so the same investigation
    always yields the same observation id.
    """

    model_config = ConfigDict(frozen=True)

    id: str = Field(min_length=1)
    rule_id: str = Field(min_length=1)
    category: CorrelationCategory
    title: str = Field(min_length=1)
    summary: str = ""
    subject_type: EntityType
    subject_value: str = Field(min_length=1)
    evidence: tuple[CorrelationEvidence, ...] = ()
    relationships: tuple[CorrelationRelationship, ...] = ()
    source_finding_ids: tuple[str, ...] = ()


class CorrelationMatch(BaseModel):
    """A per-rule execution record: which rule fired and what it produced.

    References observations by id (the authoritative observation objects live
    on :class:`CorrelationSummary.observations`), so a match adds provenance
    without duplicating observation data.
    """

    model_config = ConfigDict(frozen=True)

    rule_id: str = Field(min_length=1)
    category: CorrelationCategory
    observation_ids: tuple[str, ...] = ()


# --------------------------------------------------------------------------- #
# Summary (the canonical output)
# --------------------------------------------------------------------------- #


class CorrelationStatistics(BaseModel):
    """Aggregate counts over a :class:`CorrelationSummary`."""

    model_config = ConfigDict(frozen=True)

    rules_evaluated: int = Field(default=0, ge=0)
    rules_matched: int = Field(default=0, ge=0)
    total_observations: int = Field(default=0, ge=0)
    source_finding_count: int = Field(default=0, ge=0)
    categories: frozenset[CorrelationCategory] = frozenset()


class CorrelationMetadata(BaseModel):
    """Provenance for a :class:`CorrelationSummary`."""

    model_config = ConfigDict(frozen=True)

    entity_type: EntityType
    entity_value: str
    generated_at: datetime  # inherited from the source summary — never the wall clock
    framework_version: str
    source_engine_version: str


class CorrelationSummary(BaseModel):
    """Every correlation observation about one investigation, merged.

    The canonical output of :class:`~threatlens.correlation.service.CorrelationService`.
    With no rules matching (e.g. an empty investigation) every summary is empty
    by construction — the real aggregation path, not a special-cased stub.
    Content-addressed ``id`` excludes ``generated_at`` so re-running correlation
    on the same investigation yields the same id.
    """

    model_config = ConfigDict(frozen=True)

    id: str = Field(min_length=1)
    entity_type: EntityType
    entity_value: str
    observations: tuple[CorrelationObservation, ...] = ()
    matches: tuple[CorrelationMatch, ...] = ()
    statistics: CorrelationStatistics
    metadata: CorrelationMetadata
    source_finding_ids: tuple[str, ...] = ()

    @property
    def has_observations(self) -> bool:
        return bool(self.observations)
