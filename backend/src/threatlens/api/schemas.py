"""Request/response DTOs for the detection API.

The response reuses the engine's :class:`~threatlens.entities.models.Entity`
verbatim — the API never redefines the detection contract, it only wraps it
with a per-request ``search_id`` for future history/replay (not persisted yet).
"""

from __future__ import annotations

from uuid import UUID

from pydantic import BaseModel, Field, field_validator

from ..entities.models import Entity
from ..providers import AggregatedResult

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
    """

    investigation_id: UUID
    entity: Entity
    threat_intelligence: AggregatedResult
    knowledge: AggregatedResult
