"""FastAPI application exposing the Universal Entity Detection Engine.

A single deterministic endpoint, ``POST /api/v1/detect``, classifies arbitrary
input into a normalized :class:`~threatlens.entities.models.Entity`. The engine
does the work (:func:`threatlens.search.detect`); this module only handles
transport, validation, and a per-request ``search_id``.
"""

from __future__ import annotations

import os
import time
from typing import Annotated
from uuid import uuid4

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware

from ..ai import AIExplanation, AIExplanationService, build_ai_service
from ..detection import DetectionPackage
from ..detection import build_default_registry as build_detection_registry
from ..detection import generate as generate_detections
from ..detection_library import (
    CommunityRecommendation,
    CommunitySearchResult,
    DetectionKnowledgeService,
    DetectionLanguage,
    DetectionSeverity,
    RulePlatform,
)
from ..investigation import InvestigationService
from ..providers import build_default_router
from ..reasoning import InvestigationSummary, reason
from ..reference import build_default_reference_router
from ..search import detect
from ..system import build_system_router
from ..system import registry as metrics_registry
from ..system.record import (
    record_ai_explanation,
    record_detection_generation,
    record_dkl_query,
    record_investigation,
)
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


# The Detection Engineering registry is a downstream, deterministic consumer of
# the InvestigationSummary. Built once; empty in Phase 4.0 (no generators yet).
_detection_registry = build_detection_registry()


# The Detection Knowledge Library is a separate, read-only downstream consumer:
# it indexes *community* detection content and recommends it, never generating
# rules and never touching the Detection Engine. Built once, offline-first (the
# bundled seed corpus, or a synced cache when configured) — an investigation
# never reaches the network to serve a recommendation.
_knowledge_service = DetectionKnowledgeService.from_default()


def get_knowledge_service() -> DetectionKnowledgeService:
    """Provide the Detection Knowledge Library service (overridable in tests)."""
    return _knowledge_service


# Operational-readiness endpoints. Mounted at the root (``/health``, ``/ready``,
# ``/version``, …) for infrastructure probes hitting the backend directly, and
# again under ``/api/v1`` so a same-origin frontend reaches them through the
# existing API base. Every endpoint is read-only (see ``api/health.py``).
app.include_router(health_router)
app.include_router(health_router, prefix="/api/v1")

# Operational Dashboard (read-only): system health, API consumption, and
# configuration status for administrators/developers. Isolated from the
# investigation path — see docs/architecture/PHASE-OPERATIONAL-DASHBOARD-V1.md.
app.include_router(
    build_system_router(
        detection_registry=_detection_registry,
        knowledge_service=_knowledge_service,
    ),
    prefix="/api/v1",
)


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
    _start = time.perf_counter()
    threat_intelligence, knowledge = await service.investigate(entity)
    _duration_ms = (time.perf_counter() - _start) * 1000
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
    _start = time.perf_counter()
    explanation = await service.explain(summary)
    _duration_ms = (time.perf_counter() - _start) * 1000
    if explanation.status != "disabled":
        record_ai_explanation(
            metrics_registry,
            explanation=explanation,
            prompt_chars=len(summary.model_dump_json()),
            duration_ms=_duration_ms,
        )
    return explanation


@app.post("/api/v1/detections", response_model=DetectionPackage)
def create_detections(summary: InvestigationSummary) -> DetectionPackage:
    """Convert a completed investigation into a ``DetectionPackage``.

    The input is the deterministic ``InvestigationSummary`` produced by
    ``/investigate``; the output is a content-addressed ``DetectionPackage``. The
    Detection Engine is strictly downstream and pure — it never influences
    findings, confidence, severity, priority, recommendations, or relationships,
    and it has no access to providers or AI.

    In Phase 4.0 no generators are registered, so the package is well-formed but
    carries no artifacts (``is_empty``). The endpoint and contract already exist
    so future generators light up without an API change.
    """
    _start = time.perf_counter()
    package = generate_detections(summary, registry=_detection_registry)
    _duration_ms = (time.perf_counter() - _start) * 1000
    record_detection_generation(metrics_registry, package=package, duration_ms=_duration_ms)
    return package


@app.post("/api/v1/detection-knowledge/recommend", response_model=CommunityRecommendation)
def recommend_community_detections(
    summary: InvestigationSummary,
    service: Annotated[DetectionKnowledgeService, Depends(get_knowledge_service)],
) -> CommunityRecommendation:
    """Recommend *community* detections that resemble a completed investigation.

    Strictly downstream, read-only, and deterministic (no AI, no embeddings, no
    network): the same summary always yields the same ranked exact/partial/
    related community rules. These are complementary to — never merged with — the
    generated ``DetectionPackage`` from ``/detections``; provenance (repository,
    author, license, version, URL) is preserved on every match.
    """
    _start = time.perf_counter()
    result = service.recommend(summary)
    record_dkl_query(metrics_registry, duration_ms=(time.perf_counter() - _start) * 1000)
    return result


@app.get("/api/v1/detection-knowledge/search", response_model=CommunitySearchResult)
def search_community_detections(
    service: Annotated[DetectionKnowledgeService, Depends(get_knowledge_service)],
    ioc: str | None = None,
    technique: str | None = None,
    actor: str | None = None,
    malware: str | None = None,
    name: str | None = None,
    tag: str | None = None,
    rule_id: str | None = None,
    language: DetectionLanguage | None = None,
    repository: str | None = None,
    min_severity: DetectionSeverity | None = None,
    platform: RulePlatform | None = None,
    text: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> CommunitySearchResult:
    """Search the offline community library by any combination of axes (AND).

    Every filter is optional; results are returned in a stable, deterministic
    order with a snapshot of library stats. Read-only and offline.
    """
    _start = time.perf_counter()
    result = service.search(
        ioc=ioc,
        technique=technique,
        actor=actor,
        malware=malware,
        name=name,
        tag=tag,
        rule_id=rule_id,
        language=language,
        repository=repository,
        min_severity=min_severity,
        platform=platform,
        text=text,
        limit=limit,
        offset=offset,
    )
    record_dkl_query(metrics_registry, duration_ms=(time.perf_counter() - _start) * 1000)
    return result
