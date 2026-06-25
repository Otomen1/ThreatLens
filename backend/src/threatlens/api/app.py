"""FastAPI application exposing the Universal Entity Detection Engine.

A single deterministic endpoint, ``POST /api/v1/detect``, classifies arbitrary
input into a normalized :class:`~threatlens.entities.models.Entity`. The engine
does the work (:func:`threatlens.search.detect`); this module only handles
transport, validation, and a per-request ``search_id``.
"""

from __future__ import annotations

import os
from uuid import uuid4

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from ..search import detect
from .schemas import DetectRequest, DetectResponse

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
