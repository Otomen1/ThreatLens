"""Request/response DTOs for the detection API.

The response reuses the engine's :class:`~threatlens.entities.models.Entity`
verbatim — the API never redefines the detection contract, it only wraps it
with a per-request ``search_id`` for future history/replay (not persisted yet).
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field, field_validator

from ..entities.models import Entity
from ..entities.types import EntityType
from ..exposure import ExposureSummary
from ..providers import AggregatedResult
from ..reasoning import InvestigationSummary, Severity
from ..workspace import WorkspaceStatus

# Generous upper bound for a single query (long URLs, registry keys) while still
# rejecting obvious abuse and keeping request handling cheap.
MAX_QUERY_LENGTH = 4096


class DetectRequest(BaseModel):
    """A single detection request."""

    query: str = Field(min_length=1, max_length=MAX_QUERY_LENGTH)

    @field_validator("query")
    @classmethod
    def _not_blank(cls, value: str) -> str:
        """Reject whitespace-only queries; hand the engine a stripped value."""
        stripped = value.strip()
        if not stripped:
            raise ValueError("query must not be blank")
        return stripped


class DetectResponse(BaseModel):
    """A detection result plus a per-request search id (not persisted yet)."""

    search_id: UUID
    entity: Entity


class InvestigationResponse(BaseModel):
    """Unified investigation: entity + TI framework + reference knowledge.

    ``threat_intelligence`` aggregates external provider findings (reputation,
    evidence, relationships). ``knowledge`` aggregates reference-knowledge
    findings (MITRE ATT&CK, CVE/NVD, …). Either may be empty when no providers
    support the entity type — the client hides those sections rather than
    receiving an error.

    ``investigation_summary`` is the deterministic Investigation Intelligence
    Engine output (Phase 3). In 3.1a it carries the evidence-derived overall
    confidence; findings and recommendations arrive in later slices.
    """

    investigation_id: UUID
    entity: Entity
    threat_intelligence: AggregatedResult
    knowledge: AggregatedResult
    investigation_summary: InvestigationSummary


class ExposureProviderStatusInfo(BaseModel):
    """A point-in-time health snapshot for one exposure provider, over the API."""

    name: str
    display_name: str
    status: str
    detail: str | None = None


class ExposureFrameworkStatus(BaseModel):
    """Exposure Intelligence Framework status, and optionally a real lookup.

    With no lookup requested, this is a pure status probe: framework
    version, registered-provider count, and each provider's health — never
    exposure data. When a ``value`` is supplied to the endpoint, ``summary``
    additionally carries that entity's merged ``ExposureSummary`` from every
    routed provider (Shodan today). Still not integrated into ``/investigate``.
    """

    status: str
    message: str
    framework_version: str
    providers_registered: int
    providers: list[ExposureProviderStatusInfo] = Field(default_factory=list)
    summary: ExposureSummary | None = None


class IdentityFrameworkStatus(BaseModel):
    """Identity Intelligence Framework status (Phase 6.0 — framework only).

    A pure readiness probe: framework version and registered-provider count.
    Phase 6.0 ships zero providers, so ``providers_registered`` is 0 and no
    entity lookup is ever performed. Not integrated into ``/investigate``.
    Mirrors the Phase 5.0 exposure framework-status probe; a later phase adds
    per-provider health and an optional lookup exactly as exposure did.
    """

    status: str
    message: str
    framework_version: str
    providers_registered: int


class CorrelationFrameworkStatus(BaseModel):
    """Investigation Correlation Engine status (Phase 7.0 — framework only).

    A pure readiness probe: framework version and the count of registered
    correlation rules. Phase 7.0 ships a small seed rule set and performs no
    correlation from this endpoint (it never touches an investigation). Not
    integrated into ``/investigate`` yet.
    """

    status: str
    message: str
    framework_version: str
    rules_registered: int


class WorkspaceListItem(BaseModel):
    """One row of ``GET /api/v1/workspace`` — metadata only.

    Deliberately excludes the nested ``investigation_summary``/
    ``detection_package``/``correlation_summary`` payloads: a list of many
    saved investigations only needs the metadata columns (mirrors the
    "Investigation metadata" fields), not every attached engine output. The
    full record — including those payloads — is available from
    ``GET /api/v1/workspace/{id}``.
    """

    id: UUID
    title: str
    created_at: datetime
    updated_at: datetime
    status: WorkspaceStatus
    tags: list[str]
    summary: str | None
    severity: Severity | None
    investigation_type: EntityType


class WorkspaceListResponse(BaseModel):
    """The full result of ``GET /api/v1/workspace``: matching rows plus a count."""

    investigations: list[WorkspaceListItem]
    total: int
