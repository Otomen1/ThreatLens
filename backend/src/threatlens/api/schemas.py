"""Request/response DTOs for the detection API.

The response reuses the engine's :class:`~threatlens.entities.models.Entity`
verbatim — the API never redefines the detection contract, it only wraps it
with a per-request ``search_id`` for future history/replay (not persisted yet).
"""

from __future__ import annotations

from uuid import UUID

from pydantic import BaseModel, Field, field_validator

from ..entities.models import Entity
from ..exposure import ExposureSummary
from ..providers import AggregatedResult
from ..reasoning import InvestigationSummary

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
