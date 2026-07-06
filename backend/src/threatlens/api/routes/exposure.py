"""Exposure Intelligence route: framework + provider status, and an optional real lookup.

Answers "where is this entity exposed", never "is it malicious" (that remains
Threat Intelligence's question) — a separate framework at every layer. Not
integrated into ``/investigate``: a dedicated, isolated lookup.
"""

from __future__ import annotations

import asyncio
from typing import Annotated

from fastapi import APIRouter, Query

from ...exposure import EXPOSURE_FRAMEWORK_VERSION, ExposureService
from ...exposure import build_default_registry as build_exposure_registry
from ...search import detect
from ..schemas import MAX_QUERY_LENGTH, ExposureFrameworkStatus, ExposureProviderStatusInfo

router = APIRouter()

# Exposure Intelligence: a separate framework answering "where is this
# entity exposed", never "is it malicious" (that remains Threat
# Intelligence's question). Built once — Phase 5.1 registers the first
# concrete provider (Shodan); see
# docs/architecture/PHASE-5.0-EXPOSURE-FRAMEWORK.md and
# docs/architecture/PHASE-5.1-SHODAN-PROVIDER.md.
_exposure_registry = build_exposure_registry()
_exposure_service = ExposureService(_exposure_registry)


@router.get("/api/v1/exposure", response_model=ExposureFrameworkStatus)
async def exposure_framework_status(
    value: Annotated[str | None, Query(max_length=MAX_QUERY_LENGTH)] = None,
) -> ExposureFrameworkStatus:
    """Report Exposure Intelligence Framework + provider status, or run a real lookup.

    With no ``value``, this is a pure status probe: framework version,
    registered-provider count, and each provider's health (Shodan today) —
    never an entity lookup. With ``value``, additionally detects the entity
    and runs it through every routed exposure provider, returning their
    merged ``ExposureSummary``. A disabled or unconfigured provider (e.g.
    ``SHODAN_ENABLED=false`` or no ``SHODAN_API_KEY``) yields a well-formed,
    empty or ``unauthorized`` summary — never an error. Still never
    integrated into ``/investigate``.
    """
    providers = _exposure_registry.providers
    health = await asyncio.gather(*(p.health() for p in providers))
    provider_info = [
        ExposureProviderStatusInfo(
            name=provider.metadata.name,
            display_name=provider.metadata.display_name,
            status=snapshot.status,
            detail=snapshot.detail,
        )
        for provider, snapshot in zip(providers, health, strict=True)
    ]

    summary = None
    if value is not None and value.strip():
        entity = detect(value)
        summary = await _exposure_service.investigate(entity)

    count = len(_exposure_registry)
    return ExposureFrameworkStatus(
        status="ready",
        message="No providers configured" if count == 0 else f"{count} provider(s) registered",
        framework_version=EXPOSURE_FRAMEWORK_VERSION,
        providers_registered=count,
        providers=provider_info,
        summary=summary,
    )
