"""FastAPI application exposing the Universal Entity Detection Engine.

A single deterministic endpoint, ``POST /api/v1/detect``, classifies arbitrary
input into a normalized :class:`~threatlens.entities.models.Entity`. The engine
does the work (:func:`threatlens.search.detect`); this module only handles
transport, validation, and a per-request ``search_id``.
"""

from __future__ import annotations

import asyncio
import os
from typing import Annotated
from uuid import uuid4

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware

from ..providers import IntelligenceResult, ProviderRouter, build_default_router
from ..search import detect
from .schemas import DetectRequest, DetectResponse, IntelligenceResponse

app = FastAPI(
    title="ThreatLens API",
    version="0.1.0",
    description="Universal Entity Detection Engine (Phase 1.1.5).",
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


# Process-wide router over the default provider registry. Built once; providers
# are stateless aside from their (network-only) HTTP client.
_provider_router = build_default_router()


def get_provider_router() -> ProviderRouter:
    """Provide the provider router (overridable in tests)."""
    return _provider_router


@app.get("/api/v1/health")
def health() -> dict[str, str]:
    """Liveness probe."""
    return {"status": "ok"}


@app.post("/api/v1/detect", response_model=DetectResponse)
def detect_entity(request: DetectRequest) -> DetectResponse:
    """Classify ``request.query`` into a normalized entity.

    A well-formed request always returns ``200``: unclassifiable input resolves
    to an ``UNKNOWN``/``FREETEXT`` entity rather than an error. Malformed
    requests (missing, blank, or oversized query) are rejected with ``422``.
    """
    entity = detect(request.query)
    return DetectResponse(search_id=uuid4(), entity=entity)


@app.post("/api/v1/intelligence", response_model=IntelligenceResponse)
async def gather_intelligence(
    request: DetectRequest,
    router: Annotated[ProviderRouter, Depends(get_provider_router)],
) -> IntelligenceResponse:
    """Detect the entity, then run every capable provider concurrently.

    Returns one :class:`IntelligenceResult` per routed provider. Providers that
    fail return a failure result rather than raising, so a partial outage never
    fails the request. No merging or scoring happens here.
    """
    entity = detect(request.query)
    providers = router.route(entity)
    results: list[IntelligenceResult] = list(
        await asyncio.gather(*(provider.search(entity) for provider in providers))
    )
    return IntelligenceResponse(search_id=uuid4(), entity=entity, results=results)
