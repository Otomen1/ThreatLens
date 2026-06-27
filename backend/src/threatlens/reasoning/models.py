"""Canonical models for the Investigation Intelligence Engine (Phase 3).

These are the frozen, deterministic contracts every later reasoning phase builds
on. They reuse the existing attributed evidence/relationship models from
``providers.aggregation`` rather than redefining them; only the reasoning-layer
concepts (weighting, confidence, findings, recommendations, summary) are new.

Phase 3.1a defines the full model set but only *produces* WeightedEvidence,
Confidence and InvestigationSummary. Finding and Recommendation are model-only
here — their generation arrives in 3.1b/3.1c. InvestigationContext and derived
Priority arrive in 3.1d and are intentionally absent from this slice.
"""

from __future__ import annotations

from datetime import datetime
from enum import IntEnum, StrEnum

from pydantic import BaseModel, ConfigDict, Field

from ..entities.types import EntityType
from ..providers.aggregation import AttributedEvidence, AttributedRelationship

# --------------------------------------------------------------------------- #
# Enumerations
# --------------------------------------------------------------------------- #


class Severity(IntEnum):
    """How bad an issue is *if true*. Ordinal so findings can be compared/maxed."""

    INFORMATIONAL = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class ConfidenceBand(StrEnum):
    """A coarse, display-friendly bucket over the numeric confidence score."""

    INSUFFICIENT = "insufficient"
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    VERY_HIGH = "very_high"


class EvidencePolarity(StrEnum):
    """Whether a piece of evidence supports, contradicts, or merely frames a claim."""

    SUPPORTING = "supporting"
    CONTRADICTING = "contradicting"
    CONTEXTUAL = "contextual"


class EvidenceDimension(StrEnum):
    """The signal an evidence item speaks to (closed set — see Phase 3 spec §7)."""

    REPUTATION = "reputation"
    EXPLOITATION = "exploitation"
    EXPOSURE = "exposure"
    ATTRIBUTION = "attribution"
    WEAKNESS = "weakness"
    CAPABILITY = "capability"
    INFRASTRUCTURE = "infrastructure"


class FindingCategory(StrEnum):
    """Domain + disposition categories. A finding may hold several."""

    # domain
    MALICIOUS_INFRASTRUCTURE = "malicious_infrastructure"
    VULNERABILITY = "vulnerability"
    WEAKNESS = "weakness"
    ATTACK_PATTERN = "attack_pattern"
    THREAT_ACTOR = "threat_actor"
    MALWARE = "malware"
    CAMPAIGN = "campaign"
    EXPOSURE = "exposure"
    MISCONFIGURATION = "misconfiguration"
    REPUTATION = "reputation"
    # disposition / priority
    KNOWN_EXPLOITED = "known_exploited"
    HIGH_PRIORITY = "high_priority"
    ACTION_REQUIRED = "action_required"
    CONTESTED = "contested"
    INFORMATIONAL = "informational"


class RecommendationCategory(StrEnum):
    """Closed set of recommendation kinds (Phase 3 spec §10). Do not expand."""

    CONTAINMENT = "containment"
    INVESTIGATION = "investigation"
    REMEDIATION = "remediation"
    FORENSICS = "forensics"


class RecommendationAction(StrEnum):
    """The concrete action a recommendation proposes."""

    PATCH_IMMEDIATELY = "patch_immediately"
    MONITOR = "monitor"
    BLOCK = "block"
    INVESTIGATE = "investigate"
    THREAT_HUNT = "threat_hunt"
    GENERATE_DETECTION = "generate_detection"
    COLLECT_MEMORY = "collect_memory"
    ACQUIRE_DISK = "acquire_disk"
    ENRICH = "enrich"
    ESCALATE = "escalate"
    NO_ACTION_NEEDED = "no_action_needed"


class AssetCriticality(StrEnum):
    """How important the investigated asset is (closed set)."""

    UNKNOWN = "unknown"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Environment(StrEnum):
    """The deployment environment of the investigated asset (closed set)."""

    UNKNOWN = "unknown"
    DEVELOPMENT = "development"
    TEST = "test"
    STAGING = "staging"
    PRODUCTION = "production"


# --------------------------------------------------------------------------- #
# Investigation context (optional engine input — affects priority only)
# --------------------------------------------------------------------------- #


class InvestigationContext(BaseModel):
    """The operational frame an investigation runs in (the asset's context).

    An *optional* input to the engine. It influences only derived Priority — never
    evidence, confidence, severity, finding generation, or recommendation
    generation. The default (:data:`EMPTY_CONTEXT`) leaves the engine behaving
    exactly as a context-free investigation.
    """

    model_config = ConfigDict(frozen=True)

    criticality: AssetCriticality = AssetCriticality.UNKNOWN
    environment: Environment = Environment.UNKNOWN
    internet_facing: bool = False
    tags: list[str] = Field(default_factory=list)
    attributes: dict[str, str] = Field(default_factory=dict)


EMPTY_CONTEXT = InvestigationContext()
"""The singleton empty context: the engine behaves exactly as without context."""


# --------------------------------------------------------------------------- #
# Evidence (derived) — wraps existing AttributedEvidence, never replaces it
# --------------------------------------------------------------------------- #


class WeightedEvidence(BaseModel):
    """An assembled, weighted view over one attributed evidence item.

    ``evidence`` is the existing :class:`AttributedEvidence` (which preserves the
    underlying observation and its contributing providers). The reasoning layer
    adds a deterministic ``weight`` plus its ``polarity`` and ``dimension``.
    """

    model_config = ConfigDict(frozen=True)

    evidence: AttributedEvidence
    weight: float = Field(ge=0.0, le=1.0)
    polarity: EvidencePolarity
    dimension: EvidenceDimension


# --------------------------------------------------------------------------- #
# Confidence
# --------------------------------------------------------------------------- #


class ConfidenceFactor(BaseModel):
    """One explainable contributor to a confidence score."""

    model_config = ConfigDict(frozen=True)

    name: str = Field(min_length=1)
    contribution: int  # signed points this factor added to the score
    detail: str


class Confidence(BaseModel):
    """A deterministic confidence assessment: score + band + full explanation."""

    model_config = ConfigDict(frozen=True)

    score: int = Field(ge=0, le=100)
    band: ConfidenceBand
    contested: bool = False
    factors: list[ConfidenceFactor] = Field(default_factory=list)


# --------------------------------------------------------------------------- #
# Recommendation (model only in 3.1a)
# --------------------------------------------------------------------------- #


class Recommendation(BaseModel):
    """A deterministic, finding-owned recommended action.

    ``finding_ids`` is empty on a finding-owned recommendation (it lives inside
    its Finding, which is its context). It is populated only on the
    InvestigationSummary rollup, where recommendations are detached from their
    findings and need to retain provenance back to the originating finding ids.
    """

    model_config = ConfigDict(frozen=True)

    action: RecommendationAction
    category: RecommendationCategory
    priority: int = Field(ge=0)  # 0 = most urgent
    target_type: EntityType
    target_value: str = Field(min_length=1)
    rationale: str
    rule_id: str
    finding_ids: list[str] = Field(default_factory=list)  # populated only in the rollup


# --------------------------------------------------------------------------- #
# Finding (model only in 3.1a — generation arrives in 3.1b)
# --------------------------------------------------------------------------- #


class Finding(BaseModel):
    """A single evidence-backed conclusion about a subject entity (model only).

    Carries no mutable lifecycle status: status is owned by a future Case
    Management layer keyed on the stable ``id`` (Phase 3 spec §8).
    """

    model_config = ConfigDict(frozen=True)

    id: str = Field(min_length=1)
    title: str = Field(min_length=1)
    categories: frozenset[FindingCategory]
    subject_type: EntityType
    subject_value: str = Field(min_length=1)
    severity: Severity
    confidence: Confidence
    priority: int = Field(default=0, ge=0)  # derived in 3.1d
    evidence: list[WeightedEvidence] = Field(default_factory=list)
    relationships: list[AttributedRelationship] = Field(default_factory=list)
    sources: list[str] = Field(default_factory=list)
    rationale: str = ""
    rule_ids: list[str] = Field(default_factory=list)
    recommendations: list[Recommendation] = Field(default_factory=list)


# --------------------------------------------------------------------------- #
# Investigation summary (top-level engine output)
# --------------------------------------------------------------------------- #


class InvestigationSummary(BaseModel):
    """The Investigation Intelligence Engine's output for one entity.

    In 3.1a this carries the deterministic evidence foundation: an overall
    confidence derived from the assembled evidence. ``findings`` and the
    ``recommendations`` rollup are empty until the rule and recommendation
    engines land (3.1b/3.1c).
    """

    model_config = ConfigDict(frozen=True)

    entity_type: EntityType
    entity_value: str
    posture: Severity = Severity.INFORMATIONAL
    overall_confidence: Confidence
    categories: frozenset[FindingCategory] = frozenset()
    findings: list[Finding] = Field(default_factory=list)
    recommendations: list[Recommendation] = Field(default_factory=list)  # derived rollup
    engine_version: str
    generated_at: datetime
