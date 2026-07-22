"""FastAPI application: composition root for the ThreatLens API.

Each subsystem's endpoints live in their own router under ``api/routes/``
(plus the standalone ``health`` and ``system`` routers) and are mounted here.
This module builds the FastAPI app, configures CORS, and includes every
router â€” it holds no route handlers or business logic of its own.
"""

from __future__ import annotations

import os
import hmac
import time
from collections import defaultdict, deque
from threading import Lock

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from ..system import build_system_router
from .health import router as health_router
from .routes import (
    ai,
    cases,
    correlation,
    detection,
    detection_knowledge,
    exposure,
    identity,
    investigation,
    workspace,
)
from .routes.ai import get_ai_service as get_ai_service
from .routes.cases import get_case_service as get_case_service
from .routes.detection_knowledge import get_knowledge_service as get_knowledge_service
from .routes.investigation import get_investigation_service as get_investigation_service
from .routes.workspace import get_graph_service as get_graph_service
from .routes.workspace import get_timeline_service as get_timeline_service
from .routes.workspace import get_workspace_service as get_workspace_service

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

_API_KEY = os.getenv("THREATLENS_API_KEY", "").strip()
_RATE_LIMIT = int(os.getenv("THREATLENS_RATE_LIMIT_PER_MINUTE", "60")) if _API_KEY else 0
_RATE_BUCKETS: defaultdict[str, deque[float]] = defaultdict(deque)
_RATE_LOCK = Lock()
_PUBLIC_PATHS = {
    "/health",
    "/ready",
    "/version",
    "/api/v1/health",
    "/api/v1/ready",
    "/api/v1/version",
}

app = FastAPI(
    title="ThreatLens API",
    version="1.0.0",
    description=(
        "ThreatLens Core Platform v1.0 â€” deterministic entity detection, "
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
    # PUT/DELETE are needed by the Investigation Workspace (Phase 8.0) update
    # and delete endpoints; PATCH is needed by Case Management's (Phase 9.0)
    # partial-update endpoint; every other route remains GET/POST only.
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=["*"],
)


@app.middleware("http")
async def protect_api(request: Request, call_next):
    """Protect deployed API instances when an API key is configured.

    Local development remains unchanged when ``THREATLENS_API_KEY`` is unset;
    deployed instances should always set it through the platform secret store.
    Health probes stay public, while all other API routes require the key and
    are rate-limited per client IP.
    """
    path = request.url.path
    if _API_KEY and path.startswith("/api/v1") and path not in _PUBLIC_PATHS:
        supplied = request.headers.get("x-api-key", "")
        if not hmac.compare_digest(supplied, _API_KEY):
            return JSONResponse(status_code=401, content={"detail": "Invalid API key"})

        if _RATE_LIMIT > 0:
            now = time.monotonic()
            client = request.client.host if request.client else "unknown"
            with _RATE_LOCK:
                bucket = _RATE_BUCKETS[client]
                while bucket and now - bucket[0] >= 60:
                    bucket.popleft()
                if len(bucket) >= _RATE_LIMIT:
                    return JSONResponse(status_code=429, content={"detail": "Rate limit exceeded"})
                bucket.append(now)
    return await call_next(request)

# Operational-readiness endpoints. Mounted at the root (``/health``, ``/ready``,
# ``/version``, â€¦) for infrastructure probes hitting the backend directly, and
# again under ``/api/v1`` so a same-origin frontend reaches them through the
# existing API base. Every endpoint is read-only (see ``api/health.py``).
app.include_router(health_router)
app.include_router(health_router, prefix="/api/v1")

# Operational Dashboard (read-only): system health, API consumption, and
# configuration status for administrators/developers. Isolated from the
# investigation path â€” see docs/architecture/PHASE-OPERATIONAL-DASHBOARD-V1.md.
# Reads the same singleton DetectionRegistry / DetectionKnowledgeService their
# own routers below already built â€” never a second copy.
app.include_router(
    build_system_router(
        detection_registry=detection.detection_registry,
        knowledge_service=detection_knowledge.knowledge_service,
    ),
    prefix="/api/v1",
)

# Core entity detection + investigation (TI + reference providers, reasoning).
app.include_router(investigation.router)

# Investigation Workspace: a persistence layer over completed investigations
# (save/load/update/delete/list), plus two read-only, derived sibling views â€”
# an investigation timeline (Phase 8.1) and an evidence relationship graph
# (Phase 8.2). Consumes existing outputs; never generates them and never
# touches the analytical pipeline above.
app.include_router(workspace.router)

# Case Management (Phase 9.0): an operational layer *above* the Workspace
# platform, organizing zero or more saved investigations by reference (id
# only). Depends on the Workspace service above to confirm a linked id
# exists; never reads, mutates, or recomputes an investigation's content,
# and Workspace itself has no notion of cases.
app.include_router(cases.router)

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
