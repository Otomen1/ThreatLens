"""Investigation routes: entity detection and the core TI + knowledge investigation.

``POST /api/v1/detect`` classifies arbitrary input into a normalized
:class:`~threatlens.entities.models.Entity`. ``POST /api/v1/investigate``
additionally runs TI + reference providers concurrently and reasons over the
result. Both are thin transport: the engine and the investigation service do
the work.
"""

from __future__ import annotations

import asyncio
import time
from typing import Annotated
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException

from ...correlation import CorrelationService
from ...exposure import ExposureService
from ...exposure import build_default_registry as build_exposure_registry
from ...identity import IdentityService
from ...identity import build_default_registry as build_identity_registry
from ...investigation import InvestigationService
from ...providers import build_default_router
from ...reasoning import reason
from ...reference import build_default_reference_router
from ...search import BatchIocLimitExceeded, detect, extract_iocs
from ...system import registry as metrics_registry
from ...system.record import record_investigation
from ..schemas import BatchInvestigationItem, BatchInvestigationResponse, DetectRequest, DetectResponse, InvestigationResponse
from ..timing import elapsed_ms

router = APIRouter()

# Process-wide investigation service. Built once; providers are stateless
# aside from their (network-only) HTTP client.
_investigation_service = InvestigationService(
    build_default_router(), build_default_reference_router()
)
_exposure_service = ExposureService(build_exposure_registry())
_correlation_service = CorrelationService()
_identity_service = IdentityService(build_identity_registry())


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
    # These are additive downstream views. Exposure remains descriptive and
    # correlation consumes the frozen summary without changing its findings.
    exposure, correlation, identity = await asyncio.gather(
        _exposure_service.investigate(entity),
        asyncio.to_thread(_correlation_service.correlate, investigation_summary),
        _identity_service.investigate(entity),
    )
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
        exposure=exposure,
        correlation=correlation,
        identity=identity,
    )


@router.post("/api/v1/investigate/batch", response_model=BatchInvestigationResponse)
async def investigate_ioc_batch(
    request: DetectRequest,
    service: Annotated[InvestigationService, Depends(get_investigation_service)],
) -> BatchInvestigationResponse:
    """Extract IOCs from pasted text and investigate each independently."""
    try:
        entities = extract_iocs(request.query, detector=detect)
    except BatchIocLimitExceeded as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if not entities:
        raise HTTPException(status_code=422, detail="No supported IOC was found in the pasted text.")

    semaphore = asyncio.Semaphore(4)

    async def run(entity):
        async with semaphore:
            try:
                # Use the existing endpoint path's implementation by retaining
                # its full enrichment and deterministic reasoning sequence.
                started = time.perf_counter()
                ti, knowledge = await service.investigate(entity)
                summary = reason(entity, ti, knowledge)
                exposure, correlation, identity = await asyncio.gather(
                    _exposure_service.investigate(entity),
                    asyncio.to_thread(_correlation_service.correlate, summary),
                    _identity_service.investigate(entity),
                )
                record_investigation(
                    metrics_registry,
                    threat_intelligence=ti,
                    knowledge=knowledge,
                    summary=summary,
                    duration_ms=elapsed_ms(started),
                )
                return BatchInvestigationItem(
                    entity=entity,
                    status="completed",
                    investigation=InvestigationResponse(
                        investigation_id=uuid4(), entity=entity, threat_intelligence=ti,
                        knowledge=knowledge, investigation_summary=summary, exposure=exposure,
                        correlation=correlation, identity=identity,
                    ),
                )
            except Exception as exc:  # One IOC must not discard successful rows.
                return BatchInvestigationItem(entity=entity, status="failed", error=str(exc) or "Investigation failed.")

    items = await asyncio.gather(*(run(entity) for entity in entities))
    return BatchInvestigationResponse(items=items, total=len(items))
