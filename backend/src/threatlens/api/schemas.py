"""Request/response DTOs for the detection API.

The response reuses the engine's :class:`~threatlens.entities.models.Entity`
verbatim — the API never redefines the detection contract, it only wraps it
with a per-request ``search_id`` for future history/replay (not persisted yet).
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field, field_validator

from ..correlation import CorrelationSummary
from ..entities.models import Entity
from ..entities.types import EntityType
from ..exposure import ExposureSummary
from ..identity import IdentitySummary
from ..providers import AggregatedResult
from ..reasoning import InvestigationSummary, Severity
from ..workspace import WorkspaceStatus

# Generous upper bound for a single query (long URLs, registry keys) while still
# rejecting obvious abuse and keeping request handling cheap.
MAX_QUERY_LENGTH = 4096


class ScanMode(StrEnum):
    """Quota-aware provider breadth for an investigation."""

    FAST = "fast"
    STANDARD = "standard"
    FULL = "full"


class DetectRequest(BaseModel):
    """A single detection request."""

    query: str = Field(min_length=1, max_length=MAX_QUERY_LENGTH)
    scan_mode: ScanMode = ScanMode.STANDARD
    excluded_providers: list[str] = Field(default_factory=list, max_length=20)
    refresh: bool = False

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


class InvestigationCacheMetadata(BaseModel):
    """Freshness information without exposing cache internals."""

    status: str = "miss"
    cached_at: datetime | None = None
    expires_at: datetime | None = None
    age_seconds: int | None = None


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
    # Additive downstream projections. These do not alter the frozen reasoning
    # summary; they make the completed investigation useful as one response.
    exposure: ExposureSummary | None = None
    correlation: CorrelationSummary | None = None
    identity: IdentitySummary | None = None
    scan_mode: ScanMode = ScanMode.STANDARD
    routed_providers: list[str] = Field(default_factory=list)
    cache: InvestigationCacheMetadata = Field(default_factory=InvestigationCacheMetadata)


class BatchItemStatus(StrEnum):
    """Closed set of states used by server and progressive clients."""

    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class BatchInvestigationItem(BaseModel):
    """One independently processed IOC in a batch investigation."""

    entity: Entity
    status: BatchItemStatus
    investigation: InvestigationResponse | None = None
    error: str | None = None
    error_code: str | None = None
    retryable: bool = False


class BatchPreviewResponse(BaseModel):
    """Safe extraction preview before any provider is contacted."""

    entities: list[Entity]
    supported: int
    duplicates: int
    invalid: int
    estimated_ti_requests: int
    requires_confirmation: bool
    quota_warning: str | None = None
    single_entity: Entity | None = None
    cached_items: int = 0
    estimated_uncached_calls: int = 0
    scan_mode: ScanMode = ScanMode.STANDARD
    quota_warnings: list[str] = Field(default_factory=list)


class BatchInvestigationResponse(BaseModel):
    """Grouped results for a free-form multi-IOC search."""

    items: list[BatchInvestigationItem]
    total: int


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


class IdentityProviderStatusInfo(BaseModel):
    name: str
    display_name: str
    enabled: bool
    configured: bool
    status: str
    detail: str | None = None


class IdentityFrameworkStatus(BaseModel):
    """Identity Intelligence status and optional backward-compatible lookup."""

    status: str
    message: str
    framework_version: str
    providers_registered: int
    enabled: bool = False
    providers: list[IdentityProviderStatusInfo] = Field(default_factory=list)
    summary: IdentitySummary | None = None


class IdentityEmailCheckRequest(BaseModel):
    email: str = Field(min_length=3, max_length=320)
    refresh: bool = False


class IdentityEmailCheckResponse(BaseModel):
    summary: IdentitySummary
    cache_status: Literal["hit", "miss", "refreshed", "disabled"]
    checked_at: datetime


class PasswordHashSuffix(BaseModel):
    suffix: str = Field(pattern=r"^[A-F0-9]{35}$")
    count: int = Field(ge=0)


class PasswordRangeResponse(BaseModel):
    prefix: str = Field(pattern=r"^[A-F0-9]{5}$")
    suffixes: list[PasswordHashSuffix]
    checked_at: datetime


class CorrelationFrameworkStatus(BaseModel):
    """Investigation Correlation Engine status (Phase 7.0 — framework only).

    A pure readiness probe: framework version and the count of registered
    correlation rules. Correlation is also attached to investigations as an
    additive downstream projection.
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


class NavigationSummary(BaseModel):
    """Small read-only count snapshot for authenticated navigation badges."""

    investigations: int
    draft_detections: int
    open_cases: int
    generated_at: datetime
