"""Investigation routes: entity detection and the core TI + knowledge investigation.

``POST /api/v1/detect`` classifies arbitrary input into a normalized
:class:`~threatlens.entities.models.Entity`. ``POST /api/v1/investigate``
additionally runs TI + reference providers concurrently and reasons over the
result. Both are thin transport: the engine and the investigation service do
the work.
"""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import UTC, datetime
from typing import Annotated
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException

from ...correlation import CorrelationService
from ...entities.models import Entity
from ...entities.types import EntityType
from ...exposure import ExposureService
from ...exposure import build_default_registry as build_exposure_registry
from ...identity.runtime import service as identity_service
from ...investigation import InvestigationCache, InvestigationService, cache_key
from ...providers import build_default_router
from ...reasoning import reason
from ...reference import build_default_reference_router
from ...search import BatchIocLimitExceeded, detect, extract_ioc_report
from ...system import registry as metrics_registry
from ...system.record import record_investigation
from ..schemas import (
    BatchInvestigationItem,
    BatchInvestigationResponse,
    BatchItemStatus,
    BatchPreviewResponse,
    DetectRequest,
    DetectResponse,
    InvestigationCacheMetadata,
    InvestigationResponse,
)
from ..timing import elapsed_ms

router = APIRouter()
logger = logging.getLogger(__name__)
_FALLBACK_TYPES = {EntityType.FREETEXT, EntityType.UNKNOWN}

# Process-wide investigation service. Built once; providers are stateless
# aside from their (network-only) HTTP client.
_investigation_service = InvestigationService(
    build_default_router(), build_default_reference_router()
)
_exposure_service = ExposureService(build_exposure_registry())
_correlation_service = CorrelationService()
_investigation_cache = InvestigationCache()


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
    return await _run_investigation(entity, request=request, service=service)


async def _run_investigation(
    entity: Entity, *, request: DetectRequest, service: InvestigationService
) -> InvestigationResponse:
    excluded = frozenset(request.excluded_providers)
    routed = service.routed_provider_names(
        entity, scan_mode=request.scan_mode.value, excluded_providers=excluded
    )
    key = cache_key(
        entity_type=entity.type.value,
        value=entity.normalized_value,
        scan_mode=request.scan_mode.value,
        providers=routed,
    )
    cache_enabled = service is _investigation_service
    if cache_enabled and not request.refresh:
        cached = _investigation_cache.get(key)
        if cached is not None:
            now = datetime.now(UTC)
            response = InvestigationResponse.model_validate(cached.payload)
            return response.model_copy(
                update={
                    "cache": InvestigationCacheMetadata(
                        status="hit",
                        cached_at=cached.cached_at,
                        expires_at=cached.expires_at,
                        age_seconds=max(0, int((now - cached.cached_at).total_seconds())),
                    )
                }
            )
    _start = time.perf_counter()
    threat_intelligence, knowledge = await service.investigate(
        entity, scan_mode=request.scan_mode.value, excluded_providers=excluded
    )
    _duration_ms = elapsed_ms(_start)
    investigation_summary = reason(entity, threat_intelligence, knowledge)
    # These are additive downstream views. Exposure remains descriptive and
    # correlation consumes the frozen summary without changing its findings.
    correlation = await asyncio.to_thread(_correlation_service.correlate, investigation_summary)
    exposure = identity = None
    if request.scan_mode.value == "full":
        exposure, identity = await asyncio.gather(
            _exposure_service.investigate(entity), identity_service.investigate(entity)
        )
    record_investigation(
        metrics_registry,
        threat_intelligence=threat_intelligence,
        knowledge=knowledge,
        summary=investigation_summary,
        duration_ms=_duration_ms,
    )
    response = InvestigationResponse(
        investigation_id=uuid4(),
        entity=entity,
        threat_intelligence=threat_intelligence,
        knowledge=knowledge,
        investigation_summary=investigation_summary,
        exposure=exposure,
        correlation=correlation,
        identity=identity,
        scan_mode=request.scan_mode,
        routed_providers=routed,
    )
    if not cache_enabled:
        return response
    entry = _investigation_cache.set(key, response)
    return response.model_copy(
        update={
            "cache": InvestigationCacheMetadata(
                status="refreshed" if request.refresh else "miss",
                cached_at=entry.cached_at,
                expires_at=entry.expires_at,
                age_seconds=0,
            )
        }
    )


@router.post("/api/v1/investigate/batch", response_model=BatchInvestigationResponse)
async def investigate_ioc_batch(
    request: DetectRequest,
    service: Annotated[InvestigationService, Depends(get_investigation_service)],
) -> BatchInvestigationResponse:
    """Extract IOCs from pasted text and investigate each independently."""
    try:
        report = extract_ioc_report(request.query, detector=detect)
    except BatchIocLimitExceeded as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    entities = list(report.entities)
    if not entities:
        single = detect(request.query)
        if single.type in _FALLBACK_TYPES:
            raise HTTPException(
                status_code=422,
                detail="No supported IOC was found in the pasted text.",
            )
        entities = [single]

    batch_request_id = uuid4()
    semaphore = asyncio.Semaphore(4)

    async def run(entity: Entity) -> BatchInvestigationItem:
        async with semaphore:
            try:
                investigation = await _run_investigation(entity, request=request, service=service)
                return BatchInvestigationItem(
                    entity=entity,
                    status=BatchItemStatus.COMPLETED,
                    investigation=investigation,
                )
            except Exception:  # One IOC must not discard successful rows.
                logger.exception(
                    "Batch request %s failed for entity type %s",
                    batch_request_id,
                    entity.type.value,
                )
                return BatchInvestigationItem(
                    entity=entity,
                    status=BatchItemStatus.FAILED,
                    error="Investigation failed. You can retry this item.",
                    error_code="investigation_failed",
                    retryable=True,
                )

    items = await asyncio.gather(*(run(entity) for entity in entities))
    return BatchInvestigationResponse(items=items, total=len(items))


@router.post("/api/v1/investigate/batch/preview", response_model=BatchPreviewResponse)
def preview_ioc_batch(
    request: DetectRequest,
    service: Annotated[InvestigationService, Depends(get_investigation_service)],
) -> BatchPreviewResponse:
    """Extract and estimate a batch without contacting intelligence providers."""
    try:
        report = extract_ioc_report(request.query, detector=detect)
    except BatchIocLimitExceeded as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    entities = list(report.entities)
    single = None
    if not entities:
        detected = detect(request.query)
        if detected.type not in _FALLBACK_TYPES:
            single = detected
            entities = [detected]
    if not entities:
        raise HTTPException(status_code=422, detail="No supported indicator or entity was found.")
    excluded = frozenset(request.excluded_providers)
    cached_items = 0
    estimate = 0
    provider_estimates: dict[str, int] = {}
    for entity in entities:
        routed = service.routed_provider_names(
            entity, scan_mode=request.scan_mode.value, excluded_providers=excluded
        )
        key = cache_key(
            entity_type=entity.type.value,
            value=entity.normalized_value,
            scan_mode=request.scan_mode.value,
            providers=routed,
        )
        if (
            service is _investigation_service
            and not request.refresh
            and _investigation_cache.get(key) is not None
        ):
            cached_items += 1
        else:
            estimate += len(routed)
            for provider in routed:
                provider_estimates[provider] = provider_estimates.get(provider, 0) + 1
    requires_confirmation = len(entities) >= 6
    warning = None
    if requires_confirmation:
        warning = (
            "Large batches may consume free-provider quotas. The estimate covers routed "
            "threat-intelligence providers only."
        )
    quota_warnings = []
    for provider, requests in sorted(provider_estimates.items()):
        remaining = metrics_registry.provider_quota.get(provider, {}).get("remaining")
        if isinstance(remaining, int) and requests >= remaining:
            quota_warnings.append(
                f"{provider} reports {remaining} requests remaining; "
                f"this batch estimates {requests}."
            )
    return BatchPreviewResponse(
        entities=entities,
        supported=len(entities),
        duplicates=report.duplicates,
        invalid=report.invalid,
        estimated_ti_requests=estimate,
        requires_confirmation=requires_confirmation,
        quota_warning=warning,
        single_entity=single,
        cached_items=cached_items,
        estimated_uncached_calls=estimate,
        scan_mode=request.scan_mode,
        quota_warnings=quota_warnings,
    )
