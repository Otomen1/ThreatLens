"""FastAPI application exposing the Universal Entity Detection Engine.

A single deterministic endpoint, ``POST /api/v1/detect``, classifies arbitrary
input into a normalized :class:`~threatlens.entities.models.Entity`. The engine
does the work (:func:`threatlens.search.detect`); this module only handles
transport, validation, and a per-request ``search_id``.
"""

from __future__ import annotations

import os
from typing import Annotated
from uuid import uuid4

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware

from ..ai import AIExplanation, AIExplanationService, build_ai_service
from ..investigation import InvestigationService
from ..providers import build_default_router
from ..reasoning import InvestigationSummary, reason
from ..reference import build_default_reference_router
from ..search import detect
from .health import router as health_router
from .schemas import DetectRequest, DetectResponse, InvestigationResponse

# Local-development convenience: load backend/.env (if present) before anything
# reads the environment, so secrets like MALWAREBAZAAR_AUTH_KEY are available.
# Platforms that inject env vars directly (e.g. Vercel) have no .env, so this is
# a harmless no-op there. python-dotenv is a dev-only dependency.
try:
    from dotenv import load_dotenv
except ModuleNotFoundError:
    pass
else:
    load_dotenv()

app = FastAPI(
    title="ThreatLens API",
    version="1.0.0",
    description=(
        "ThreatLens Core Platform v1.0 — deterministic entity detection, "
        "threat-intelligence and knowledge investigation, reasoning, and "
        "optional downstream AI explanation."
    ),
)

# Same-origin deployments need no CORS; a separately-hosted or local-dev
# frontend does. Allowed origins are env-driven, defaulting to local dev hosts.
_origins = [
    origin.strip()
    for origin in os.getenv(
        "THREATLENS_CORS_ORIGINS",
        "http://localhost:3000,http://127.0.0.1:3000",
    ).split(",")
    if origin.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_origins,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


# Process-wide routers and investigation service. Built once; providers are
# stateless aside from their (network-only) HTTP client.
_investigation_service = InvestigationService(
    build_default_router(), build_default_reference_router()
)


def get_investigation_service() -> InvestigationService:
    """Provide the investigation service (overridable in tests)."""
    return _investigation_service


# The AI explanation service is downstream and optional; built once from the
# environment. It is disabled by default, so ThreatLens behaves identically when
# no AI provider is configured or running.
_ai_service = build_ai_service()


def get_ai_service() -> AIExplanationService:
    """Provide the AI explanation service (overridable in tests)."""
    return _ai_service


# Operational-readiness endpoints. Mounted at the root (``/health``, ``/ready``,
# ``/version``, …) for infrastructure probes hitting the backend directly, and
# again under ``/api/v1`` so a same-origin frontend reaches them through the
# existing API base. Every endpoint is read-only (see ``api/health.py``).
app.include_router(health_router)
app.include_router(health_router, prefix="/api/v1")


@app.post("/api/v1/detect", response_model=DetectResponse)
def detect_entity(request: DetectRequest) -> DetectResponse:
    """Classify ``request.query`` into a normalized entity.

    A well-formed request always returns ``200``: unclassifiable input resolves
    to an ``UNKNOWN``/``FREETEXT`` entity rather than an error. Malformed
    requests (missing, blank, or oversized query) are rejected with ``422``.
    """
    entity = detect(request.query)
    return DetectResponse(search_id=uuid4(), entity=entity)


@app.post("/api/v1/investigate", response_model=InvestigationResponse)
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
    threat_intelligence, knowledge = await service.investigate(entity)
    investigation_summary = reason(entity, threat_intelligence, knowledge)
    return InvestigationResponse(
        investigation_id=uuid4(),
        entity=entity,
        threat_intelligence=threat_intelligence,
        knowledge=knowledge,
        investigation_summary=investigation_summary,
    )


@app.post("/api/v1/explain", response_model=AIExplanation)
async def explain_investigation(
    summary: InvestigationSummary,
    service: Annotated[AIExplanationService, Depends(get_ai_service)],
) -> AIExplanation:
    """Explain a completed investigation with the configured AI provider.

    The input is the deterministic ``InvestigationSummary`` produced by
    ``/investigate``; the output is an :class:`AIExplanation`. This endpoint is
    strictly downstream — the AI never influences findings, confidence, severity,
    priority, or recommendations, and it has no access to providers.

    It always returns ``200``: a disabled provider or an unreachable model yields
    a structured ``disabled`` / ``unavailable`` response (never an error), so the
    AI layer can never fail an investigation. ``/investigate`` is unchanged.
    """
    return await service.explain(summary)
