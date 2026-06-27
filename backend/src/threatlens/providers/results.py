"""The canonical ThreatLens Intelligence Result model.

Every provider — VirusTotal, AbuseIPDB, OTX, MalwareBazaar, URLhaus, and later
internal knowledge sources — normalizes its vendor-specific response into the
models defined here. Raw vendor JSON never crosses this boundary: downstream
systems (aggregation, scoring, AI, API) consume only :class:`IntelligenceResult`.

The model is vendor-neutral and deliberately expressive: it carries reputation,
structured evidence, cross-entity relationships, references, tags, provenance,
and a status that supports partial failures — but contains no scoring, no graph
logic, and no provider-specific schema. All models are frozen value objects,
matching ``entities/models.py``.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, JsonValue, model_validator

from ..entities.types import EntityType

# --------------------------------------------------------------------------- #
# Vocabularies
# --------------------------------------------------------------------------- #


class ResultStatus(StrEnum):
    """Outcome of a single provider lookup.

    Distinguishing these lets aggregation treat "no data" differently from
    "the provider failed", and lets the UI surface throttling honestly. The
    error-ish states are what make graceful partial failure possible.
    """

    OK = "ok"
    NOT_FOUND = "not_found"
    UNSUPPORTED = "unsupported"
    PARTIAL = "partial"
    ERROR = "error"
    TIMEOUT = "timeout"
    RATE_LIMITED = "rate_limited"
    UNAUTHORIZED = "unauthorized"


class ReputationLevel(StrEnum):
    """A vendor-neutral reputation band.

    Never a bare boolean: a provider maps its own verdict onto this ordered
    scale, preserving nuance (see PHASE-0-ARCHITECTURE.md — evidence-first,
    non-binary results). ThreatLens-wide scoring is a later, separate concern.
    """

    UNKNOWN = "unknown"
    BENIGN = "benign"
    LIKELY_BENIGN = "likely_benign"
    SUSPICIOUS = "suspicious"
    LIKELY_MALICIOUS = "likely_malicious"
    MALICIOUS = "malicious"


class EvidenceType(StrEnum):
    """The kind of observation a piece of evidence represents.

    Structured so future scoring can weight evidence by type rather than parsing
    free text. ``OTHER`` is a forward-compatible catch-all.
    """

    CLASSIFICATION = "classification"
    DETECTION = "detection"
    ABUSE_CONFIDENCE = "abuse_confidence"
    MALWARE_FAMILY = "malware_family"
    PULSE_MATCH = "pulse_match"
    SANDBOX_OBSERVATION = "sandbox_observation"
    BLOCKLIST = "blocklist"
    CATEGORY = "category"
    COMMUNICATION = "communication"
    FIRST_SEEN = "first_seen"
    LAST_SEEN = "last_seen"
    TAG = "tag"
    OTHER = "other"


class RelationshipType(StrEnum):
    """How an entity relates to another entity (STIX SRO-aligned verbs)."""

    RELATED_TO = "related_to"
    COMMUNICATES_WITH = "communicates_with"
    RESOLVES_TO = "resolves_to"
    DOWNLOADED_FROM = "downloaded_from"
    DROPS = "drops"
    ASSOCIATED_WITH = "associated_with"
    ATTRIBUTED_TO = "attributed_to"
    PART_OF = "part_of"
    VARIANT_OF = "variant_of"
    USES = "uses"
    EXPLOITS = "exploits"
    INDICATES = "indicates"
    REFERENCED_IN = "referenced_in"


class RelationshipTargetType(StrEnum):
    """The kind of thing a relationship points to.

    A STIX-SDO-aligned superset of the detectable :class:`EntityType` values: it
    also covers concepts that cannot be detected from a raw indicator (campaign,
    report, tool, infrastructure) but are valid relationship targets. Kept
    separate from ``EntityType`` on purpose — every ``EntityType`` must have a
    detector, while these need not — so the relationship chain
    Entity → Malware → Actor → Campaign → CVE → Technique → Report is fully
    expressible today without forcing undetectable types into the engine.
    """

    INDICATOR = "indicator"
    MALWARE_FAMILY = "malware_family"
    THREAT_ACTOR = "threat_actor"
    CAMPAIGN = "campaign"
    VULNERABILITY = "vulnerability"
    WEAKNESS = "weakness"
    ATTACK_PATTERN = "attack_pattern"
    INFRASTRUCTURE = "infrastructure"
    TOOL = "tool"
    REPORT = "report"


# --------------------------------------------------------------------------- #
# Components
# --------------------------------------------------------------------------- #


class Reputation(BaseModel):
    """A provider's own reputation assessment of the entity.

    Carries the provider's normalized verdict, not a ThreatLens score. Detailed
    detections belong in :class:`Evidence`; this is the headline.
    """

    model_config = ConfigDict(frozen=True)

    level: ReputationLevel = ReputationLevel.UNKNOWN
    score: int | None = Field(default=None, ge=0, le=100)
    malicious_count: int | None = Field(default=None, ge=0)
    total_count: int | None = Field(default=None, ge=0)
    summary: str | None = None

    @model_validator(mode="after")
    def _counts_are_consistent(self) -> Reputation:
        if (
            self.malicious_count is not None
            and self.total_count is not None
            and self.malicious_count > self.total_count
        ):
            raise ValueError("malicious_count cannot exceed total_count")
        return self


class Evidence(BaseModel):
    """A single structured observation supporting a result.

    Records facts as typed data, not prose, so scoring can later weight them.
    """

    model_config = ConfigDict(frozen=True)

    type: EvidenceType
    summary: str = Field(min_length=1)
    value: str | None = None
    confidence: int | None = Field(default=None, ge=0, le=100)
    observed_at: datetime | None = None
    data: dict[str, JsonValue] = Field(default_factory=dict)


class Relationship(BaseModel):
    """A typed edge from the searched entity to a related entity.

    Enables cross-entity pivoting and a future relationship graph; this model
    only *describes* edges, it implements no graph logic.
    """

    model_config = ConfigDict(frozen=True)

    relationship: RelationshipType = RelationshipType.RELATED_TO
    target_type: RelationshipTargetType
    target_value: str = Field(min_length=1)
    confidence: int | None = Field(default=None, ge=0, le=100)
    description: str | None = None


class Reference(BaseModel):
    """An external citation backing the result (a link to a source page)."""

    model_config = ConfigDict(frozen=True)

    title: str = Field(min_length=1)
    url: str = Field(min_length=1)
    description: str | None = None


class ResultError(BaseModel):
    """Why a provider lookup failed (or partially failed)."""

    model_config = ConfigDict(frozen=True)

    message: str = Field(min_length=1)
    retryable: bool = False
    detail: str | None = None


# --------------------------------------------------------------------------- #
# Canonical result
# --------------------------------------------------------------------------- #

_HARD_ERRORS = frozenset(
    {
        ResultStatus.ERROR,
        ResultStatus.TIMEOUT,
        ResultStatus.RATE_LIMITED,
        ResultStatus.UNAUTHORIZED,
    }
)
_NO_ERROR_STATES = frozenset({ResultStatus.OK, ResultStatus.NOT_FOUND, ResultStatus.UNSUPPORTED})


class IntelligenceResult(BaseModel):
    """The canonical, vendor-neutral result a provider returns for one entity.

    A provider produces exactly this object. A failed lookup is still a valid
    result (status + error), so aggregation can proceed when some providers
    succeed and others fail.
    """

    model_config = ConfigDict(frozen=True)

    # Provenance
    provider: str = Field(min_length=1)
    provider_display_name: str | None = None

    # Subject
    entity_type: EntityType
    entity_value: str = Field(min_length=1)

    # Outcome
    status: ResultStatus = ResultStatus.OK
    error: ResultError | None = None

    # Findings
    reputation: Reputation | None = None
    evidence: list[Evidence] = Field(default_factory=list)
    relationships: list[Relationship] = Field(default_factory=list)
    references: list[Reference] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)

    # Metadata
    fetched_at: datetime | None = None
    metadata: dict[str, JsonValue] = Field(default_factory=dict)

    @property
    def is_ok(self) -> bool:
        """True when the provider returned data successfully."""
        return self.status is ResultStatus.OK

    @property
    def is_error(self) -> bool:
        """True for hard failures (error/timeout/rate-limited/unauthorized)."""
        return self.status in _HARD_ERRORS

    @property
    def has_findings(self) -> bool:
        """True when the result carries any intelligence."""
        return bool(self.reputation or self.evidence or self.relationships)

    @model_validator(mode="after")
    def _status_and_error_agree(self) -> IntelligenceResult:
        if self.status in _HARD_ERRORS and self.error is None:
            raise ValueError(f"status {self.status.value!r} requires an error")
        if self.status in _NO_ERROR_STATES and self.error is not None:
            raise ValueError(f"status {self.status.value!r} must not carry an error")
        return self

    @classmethod
    def not_found(
        cls,
        *,
        provider: str,
        entity_type: EntityType,
        entity_value: str,
        provider_display_name: str | None = None,
    ) -> IntelligenceResult:
        """Build a result for an entity the provider has no data on."""
        return cls(
            provider=provider,
            provider_display_name=provider_display_name,
            entity_type=entity_type,
            entity_value=entity_value,
            status=ResultStatus.NOT_FOUND,
        )

    @classmethod
    def unsupported(
        cls,
        *,
        provider: str,
        entity_type: EntityType,
        entity_value: str,
        provider_display_name: str | None = None,
    ) -> IntelligenceResult:
        """Build a result for an entity type the provider does not handle.

        A structured, non-exception signal — the router normally prevents this,
        but a provider called directly still answers gracefully.
        """
        return cls(
            provider=provider,
            provider_display_name=provider_display_name,
            entity_type=entity_type,
            entity_value=entity_value,
            status=ResultStatus.UNSUPPORTED,
        )

    @classmethod
    def failure(
        cls,
        *,
        provider: str,
        entity_type: EntityType,
        entity_value: str,
        message: str,
        status: ResultStatus = ResultStatus.ERROR,
        retryable: bool = False,
        detail: str | None = None,
        provider_display_name: str | None = None,
    ) -> IntelligenceResult:
        """Build a failed result. ``status`` must be an error-ish state."""
        return cls(
            provider=provider,
            provider_display_name=provider_display_name,
            entity_type=entity_type,
            entity_value=entity_value,
            status=status,
            error=ResultError(message=message, retryable=retryable, detail=detail),
        )
