"""FastAPI application: composition root for the ThreatLens API.

Each subsystem's endpoints live in their own router under ``api/routes/``
(plus the standalone ``health`` and ``system`` routers) and are mounted here.
This module builds the FastAPI app, configures CORS, and includes every
router — it holds no route handlers or business logic of its own.
"""

from __future__ import annotations

import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from ..system import build_system_router
from .health import router as health_router
from .routes import (
    ai,
    correlation,
    detection,
    detection_knowledge,
    exposure,
    identity,
    investigation,
)
from .routes.ai import get_ai_service as get_ai_service
from .routes.detection_knowledge import get_knowledge_service as get_knowledge_service
from .routes.investigation import get_investigation_service as get_investigation_service

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

# Operational-readiness endpoints. Mounted at the root (``/health``, ``/ready``,
# ``/version``, …) for infrastructure probes hitting the backend directly, and
# again under ``/api/v1`` so a same-origin frontend reaches them through the
# existing API base. Every endpoint is read-only (see ``api/health.py``).
app.include_router(health_router)
app.include_router(health_router, prefix="/api/v1")

# Operational Dashboard (read-only): system health, API consumption, and
# configuration status for administrators/developers. Isolated from the
# investigation path — see docs/architecture/PHASE-OPERATIONAL-DASHBOARD-V1.md.
# Reads the same singleton DetectionRegistry / DetectionKnowledgeService their
# own routers below already built — never a second copy.
app.include_router(
    build_system_router(
        detection_registry=detection.detection_registry,
        knowledge_service=detection_knowledge.knowledge_service,
    ),
    prefix="/api/v1",
)

# Core entity detection + investigation (TI + reference providers, reasoning).
app.include_router(investigation.router)

# Downstream, optional AI explanation of a completed investigation.
app.include_router(ai.router)

# Downstream, deterministic Detection Engineering (generated detections), and
# the separate, read-only Detection Knowledge Library (community detections).
app.include_router(detection.router)
app.include_router(detection_knowledge.router)

# Exposure Intelligence, Identity Intelligence, and the Investigation
# Correlation Engine: three separate, isolated frameworks, each a pure
# readiness probe today (Exposure additionally runs a real lookup). None is
# integrated into ``/investigate``.
app.include_router(exposure.router)
app.include_router(identity.router)
app.include_router(correlation.router)
