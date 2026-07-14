"""Investigation routes: entity detection and the core TI + knowledge investigation.

``POST /api/v1/detect`` classifies arbitrary input into a normalized
:class:`~threatlens.entities.models.Entity`. ``POST /api/v1/investigate``
additionally runs TI + reference providers concurrently and reasons over the
result. Both are thin transport: the engine and the investigation service do
the work.
"""

from __future__ import annotations

import time
from typing import Annotated
from uuid import uuid4

from fastapi import APIRouter, Depends

from ...investigation import InvestigationService
from ...providers import build_default_router
from ...reasoning import reason
from ...reference import build_default_reference_router
from ...search import detect
from ...system import registry as metrics_registry
from ...system.record import record_investigation
from ..schemas import DetectRequest, DetectResponse, InvestigationResponse
from ..timing import elapsed_ms

router = APIRouter()

# Process-wide investigation service. Built once; providers are stateless
# aside from their (network-only) HTTP client.
_investigation_service = InvestigationService(
    build_default_router(), build_default_reference_router()
)


def get_investigation_service() -> InvestigationService:
    """Provide the investigation service (overridable in tests)."""
    return _investigation_service


@router.post("/api/v1/detect", response_model=DetectResponse)
def detect_entity(request: DetectRequest) -> DetectResponse:
    """Classify ``request.query`` into a normalized entity.

    A well-formed request always returns ``200``: unclassifiable input resolves
    to an ``UNKNOWN``/``FREETEXT`` entity rather than an error. Malformed
    requests (missing, blank, or oversized query) are rejected with ``422``.
    """
    entity = detect(request.query)
    return DetectResponse(search_id=uuid4(), entity=entity)


@router.post("/api/v1/investigate", response_model=InvestigationResponse)
async def investigate_entity(
    request: DetectRequest,
    service: Annotated[InvestigationService, Depends(get_investigation_service)],
) -> InvestigationResponse:
    """Detect the entity and run TI + reference providers concurrently.

    Returns both a ``threat_intelligence`` AggregatedResult (external provider
    findings) and a ``knowledge`` AggregatedResult (reference knowledge such as
    MITRE ATT&CK). Either may be empty — the client hides empty sections.
    Providers that fail contribute their status, not an exception.
    """
    entity = detect(request.query)
    _start = time.perf_counter()
    threat_intelligence, knowledge = await service.investigate(entity)
    _duration_ms = elapsed_ms(_start)
    investigation_summary = reason(entity, threat_intelligence, knowledge)
    record_investigation(
        metrics_registry,
        threat_intelligence=threat_intelligence,
        knowledge=knowledge,
        summary=investigation_summary,
        duration_ms=_duration_ms,
    )
    return InvestigationResponse(
        investigation_id=uuid4(),
        entity=entity,
        threat_intelligence=threat_intelligence,
        knowledge=knowledge,
        investigation_summary=investigation_summary,
    )
