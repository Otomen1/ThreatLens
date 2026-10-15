"""FastAPI application: composition root for the ThreatLens API.

Each subsystem's endpoints live in their own router under ``api/routes/``
(plus the standalone ``health`` and ``system`` routers) and are mounted here.
This module builds the FastAPI app, configures CORS, and includes every
router â€” it holds no route handlers or business logic of its own.
"""

from __future__ import annotations

import asyncio
import hmac
import json
import logging
import os
import time
from uuid import UUID, uuid4

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import RequestResponseEndpoint

from ..system import build_system_router
from .auth import (
    VerifiedIdentity,
    local_auth_bypass,
    owner_user_id,
    require_owner_identity,
    supabase_auth_config,
    verify_supabase_token,
)
from .health import router as health_router
from .rate_limit import consume_owner_request
from .routes import (
    ai,
    backup,
    cases,
    correlation,
    detection,
    detection_knowledge,
    exposure,
    identity,
    investigation,
    ioc_reports,
    poc,
    threat_feed,
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
_RATE_LIMIT = int(os.getenv("THREATLENS_RATE_LIMIT_PER_MINUTE", "60"))
_PUBLIC_PATHS = {
    "/health",
    "/ready",
    "/version",
    "/api/v1/health",
    "/api/v1/ready",
    "/api/v1/version",
}
_MAX_BACKUP_BYTES = 10_000_000

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

_logger = logging.getLogger("threatlens.api")


def _request_id(value: str | None) -> str:
    """Accept a caller trace id only when it is a valid UUID; otherwise mint one."""
    try:
        return str(UUID(value or ""))
    except ValueError:
        return str(uuid4())


@app.middleware("http")
async def request_context(request: Request, call_next: RequestResponseEndpoint) -> Response:
    """Attach one trace id to every response and emit one structured log line."""
    request_id = _request_id(request.headers.get("x-request-id"))
    request.state.request_id = request_id
    started = time.perf_counter()
    response = await call_next(request)
    elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
    response.headers["x-request-id"] = request_id
    _logger.info(
        json.dumps(
            {
                "event": "http_request",
                "request_id": request_id,
                "method": request.method,
                "path": "/api/v1/identity/password-range/[redacted]"
                if request.url.path.startswith("/api/v1/identity/password-range/")
                else request.url.path,
                "status": response.status_code,
                "duration_ms": elapsed_ms,
            },
            separators=(",", ":"),
        )
    )
    return response


@app.middleware("http")
async def protect_api(request: Request, call_next: RequestResponseEndpoint) -> Response:
    """Protect private API routes with Supabase auth or a service API key.

    Only the configured owner can access private data. The explicit local
    development bypass is never honored on Vercel. Public feed routes remain public.
    """
    path = request.url.path
    is_feed = path == "/api/v1/threat-feed" or path.startswith("/api/v1/threat-feed/")
    is_public = path in _PUBLIC_PATHS or is_feed
    if request.method == "OPTIONS":
        return await call_next(request)
    if request.method == "POST" and path.startswith("/api/v1/backup"):
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                if int(content_length) > _MAX_BACKUP_BYTES:
                    return JSONResponse(status_code=413, content={"detail": "Backup is too large"})
            except ValueError:
                return JSONResponse(status_code=400, content={"detail": "Invalid content length"})
    is_private_api = path.startswith("/api/v1") and not is_public
    auth_config = supabase_auth_config()
    if is_private_api:
        if (path == "/api/v1/auth/me" or path.startswith("/api/v1/poc/")) and auth_config is None:
            return JSONResponse(
                status_code=503, content={"detail": "Sign-in service is unavailable"}
            )
        if local_auth_bypass() and auth_config is None and not _API_KEY:
            return await call_next(request)
        owner = owner_user_id()
        if owner is None or (auth_config is None and not _API_KEY):
            return JSONResponse(
                status_code=503,
                content={"detail": "Owner authentication is not configured", "retryable": False},
            )
        supplied = request.headers.get("x-api-key", "")
        api_key_valid = bool(_API_KEY) and hmac.compare_digest(supplied, _API_KEY)
        bearer = request.headers.get("authorization", "")
        token = bearer[7:].strip() if bearer.lower().startswith("bearer ") else ""
        identity = (
            await verify_supabase_token(token, auth_config) if token and auth_config else None
        )
        if api_key_valid:
            identity = VerifiedIdentity(owner, float("inf"), "api_key")
        if identity is None:
            return JSONResponse(status_code=401, content={"detail": "Authentication required"})
        if identity.user_id != owner:
            return JSONResponse(
                status_code=403,
                content={"detail": "This personal workspace is owner-only", "retryable": False},
            )
        request.state.identity = identity
        try:
            result = await asyncio.to_thread(consume_owner_request, owner, "private", _RATE_LIMIT)
        except Exception as exc:
            _logger.error("Owner request-limit storage unavailable: %s", type(exc).__name__)
            return JSONResponse(
                status_code=503, content={"detail": "Request protection is unavailable"}
            )
        if not result.allowed:
            return JSONResponse(
                status_code=429,
                content={
                    "detail": "Rate limit exceeded",
                    "error_code": "rate_limited",
                    "retryable": True,
                },
                headers={"Retry-After": str(result.retry_after)},
            )
        identity_scope = (
            "password"
            if path.startswith("/api/v1/identity/password-range/")
            else "email"
            if path == "/api/v1/identity/email/check"
            else ""
        )
        if identity_scope:
            name = (
                "IDENTITY_PASSWORD_RATE_LIMIT_PER_MINUTE"
                if identity_scope == "password"
                else "IDENTITY_RATE_LIMIT_PER_MINUTE"
            )
            raw = os.getenv(name, "30")
            limit = int(raw) if raw.isdigit() else 30
            try:
                result = await asyncio.to_thread(
                    consume_owner_request, owner, identity_scope, limit
                )
            except Exception:
                return JSONResponse(
                    status_code=503, content={"detail": "Request protection is unavailable"}
                )
            if not result.allowed:
                return JSONResponse(
                    status_code=429,
                    content={
                        "detail": "Identity request limit reached",
                        "error_code": "rate_limited",
                        "retryable": True,
                    },
                    headers={"Retry-After": str(result.retry_after)},
                )
    return await call_next(request)


@app.get("/api/v1/auth/me")
def owner_session(request: Request, response: Response) -> dict[str, str | bool]:
    identity = require_owner_identity(request, signed_in=True)
    response.headers["Cache-Control"] = "private, no-store"
    return {"user_id": identity.user_id, "owner": True}


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
app.include_router(threat_feed.router)
app.include_router(ioc_reports.router)
app.include_router(poc.router)

# Case routes are registered first because their compact navigation summary
# has a static /workspace/navigation-summary path that must precede the
# Workspace router's /workspace/{investigation_id} UUID route.
app.include_router(cases.router)

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
app.include_router(backup.router)

# Downstream, optional AI explanation of a completed investigation.
app.include_router(ai.router)

# Downstream, deterministic Detection Engineering (generated detections), and
# the separate, read-only Detection Knowledge Library (community detections).
app.include_router(detection.router)
app.include_router(detection_knowledge.router)

# Exposure Intelligence, Identity Intelligence, and the Investigation
# Correlation Engine: separate frameworks. Exposure and correlation are also
# attached as additive context to ``/investigate``; neither changes the frozen
# reasoning summary.
app.include_router(exposure.router)
app.include_router(identity.router)
app.include_router(correlation.router)
