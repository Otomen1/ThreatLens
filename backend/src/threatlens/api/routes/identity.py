"""Identity Intelligence route: a pure framework-readiness probe (Phase 6.0)."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Query

from ...identity import IDENTITY_FRAMEWORK_VERSION, IdentityService
from ...identity import build_default_registry as build_identity_registry
from ...search import detect
from ..schemas import MAX_QUERY_LENGTH, IdentityFrameworkStatus

router = APIRouter()

# Identity Intelligence: a fourth, separate framework answering "what is known
# about this identity" (breaches, credential exposure, directory profile, …),
# never "is it malicious" or "where is it exposed" (those remain Threat and
# Exposure Intelligence's questions). Phase 6.0 is framework-only — zero
# providers; a later phase registers the first (HIBP, Entra ID, …). See
# docs/architecture/PHASE-6.0-IDENTITY-FRAMEWORK.md.
_identity_registry = build_identity_registry()
_identity_service = IdentityService(_identity_registry)


@router.get("/api/v1/identity", response_model=IdentityFrameworkStatus)
async def identity_framework_status(
    value: Annotated[str | None, Query(max_length=MAX_QUERY_LENGTH)] = None,
) -> IdentityFrameworkStatus:
    """Report Identity Intelligence Framework status (Phase 6.0 — framework only).

    A pure readiness probe: framework version and registered-provider count.
    Phase 6.0 registers zero providers, so this never performs an entity
    lookup and never touches the network — it mirrors the Phase 5.0 exposure
    framework-status probe. A later phase adds per-provider health and an
    optional lookup exactly as exposure did. Never integrated into
    ``/investigate``.
    """
    summary = None
    if value is not None and value.strip():
        summary = await _identity_service.investigate(detect(value))
    count = len(_identity_registry)
    return IdentityFrameworkStatus(
        status="ready",
        message="No providers configured" if count == 0 else f"{count} provider(s) registered",
        framework_version=IDENTITY_FRAMEWORK_VERSION,
        providers_registered=count,
        summary=summary,
    )
