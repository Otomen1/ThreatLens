"""FastAPI routes for the Operational Dashboard (Sections 1-3).

Every route here is ``GET`` and read-only: no route accepts a body, mutates
state, or triggers an investigation, a detection generation, or an AI call.
:func:`build_system_router` takes the *same* singleton ``DetectionRegistry``
and ``DetectionKnowledgeService`` that ``api/app.py`` already built for the
real endpoints — the dashboard reads from them, never builds its own copies.
Mounted under ``/api/v1/system`` by ``api/app.py``.
"""

from __future__ import annotations

from fastapi import APIRouter

from ..detection.registry import DetectionRegistry
from ..detection_library.service import DetectionKnowledgeService
from .config_status import build_config_status
from .health import build_system_health
from .metrics import MetricsRegistry
from .metrics import registry as default_metrics_registry
from .schemas import ConfigStatusResponse, SystemHealthResponse, UsageResponse
from .usage import build_usage


def build_system_router(
    *,
    detection_registry: DetectionRegistry,
    knowledge_service: DetectionKnowledgeService,
    metrics: MetricsRegistry | None = None,
) -> APIRouter:
    """Build the ``/system`` router, closing over the app's existing singletons."""
    metrics_registry = metrics or default_metrics_registry
    router = APIRouter(prefix="/system", tags=["system"])

    @router.get("/health", response_model=SystemHealthResponse)
    async def system_health() -> SystemHealthResponse:
        """Section 1 — per-service Healthy/Degraded/Offline/Disabled + overall."""
        return await build_system_health(
            detection_registry=detection_registry,
            knowledge_service=knowledge_service,
        )

    @router.get("/usage", response_model=UsageResponse)
    async def system_usage() -> UsageResponse:
        """Section 2 — incremental request/latency counters, never secrets."""
        return await build_usage(metrics=metrics_registry, knowledge_service=knowledge_service)

    @router.get("/config", response_model=ConfigStatusResponse)
    def system_config() -> ConfigStatusResponse:
        """Section 3 — configured/enabled booleans only, never credentials."""
        return build_config_status()

    return router
