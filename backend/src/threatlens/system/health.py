"""Aggregated operational health for the dashboard (Section 1: System Health).

Adds no new probing logic of its own for threat-intelligence, reference-
knowledge, or AI: it calls the existing, already-tested checks in
``api/health.py`` (Phase 3.17) and rolls each one up into a single
Healthy/Degraded/Offline/Disabled state. It adds two checks that
``api/health.py`` does not cover — the Detection Engine and the Detection
Knowledge Library — both purely local, in-process reads with no network
access, matching every other check here.

The ``api.health`` import is deferred to call time (rather than module load
time) so this module never participates in ``api/app.py``'s import order —
it has no opinion on when the API package finishes initializing.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from ..detection.registry import DetectionRegistry
from ..detection_library.service import DetectionKnowledgeService
from .schemas import ServiceState, ServiceStatus, SystemHealthResponse

if TYPE_CHECKING:
    from ..api.health import AIHealth


def _now() -> str:
    return datetime.now(UTC).isoformat()


async def build_system_health(
    *,
    detection_registry: DetectionRegistry,
    knowledge_service: DetectionKnowledgeService,
) -> SystemHealthResponse:
    """Build the Section 1 payload by reusing the existing health checks."""
    from ..api.health import ai_health, knowledge_health, providers_health

    services: list[ServiceStatus] = [
        ServiceStatus(
            name="backend",
            display_name="Backend",
            status=ServiceState.HEALTHY,
            detail="The API process is running.",
        ),
        ServiceStatus(
            name="api",
            display_name="API",
            status=ServiceState.HEALTHY,
            detail="API routes are serving requests.",
        ),
    ]

    ti = providers_health()
    services.append(
        ServiceStatus(
            name="threat_intelligence",
            display_name="Threat Intelligence Providers",
            status=ServiceState.HEALTHY if ti.status == "ok" else ServiceState.DEGRADED,
            detail=f"{ti.configured}/{ti.total} provider(s) configured.",
        )
    )

    kb = knowledge_health()
    services.append(
        ServiceStatus(
            name="knowledge",
            display_name="Knowledge Providers",
            status=ServiceState.HEALTHY if kb.status == "ok" else ServiceState.DEGRADED,
            detail=f"{kb.loaded}/{kb.total} reference dataset(s) loaded.",
        )
    )

    ai = await ai_health()
    services.append(_ai_service_status(ai))
    services.append(_detection_engine_status(detection_registry))
    services.append(_detection_knowledge_status(knowledge_service))

    overall = _rollup(s.status for s in services)
    return SystemHealthResponse(status=overall, services=services, timestamp=_now())


_AI_STATUS_MAP = {
    "disabled": ServiceState.DISABLED,
    "ok": ServiceState.HEALTHY,
    "unavailable": ServiceState.OFFLINE,
    "error": ServiceState.OFFLINE,
}


def _ai_service_status(ai: AIHealth) -> ServiceStatus:
    detail = ai.detail or "AI reachability probe completed."
    return ServiceStatus(
        name="ai",
        display_name="AI Provider",
        status=_AI_STATUS_MAP.get(ai.status, ServiceState.OFFLINE),
        detail=detail if ai.status != "disabled" else "The AI explanation layer is disabled.",
    )


def _detection_engine_status(registry: DetectionRegistry) -> ServiceStatus:
    healthy = len(registry) > 0
    return ServiceStatus(
        name="detection_engine",
        display_name="Detection Engine",
        status=ServiceState.HEALTHY if healthy else ServiceState.DEGRADED,
        detail=f"{len(registry)} generator(s) registered.",
    )


def _detection_knowledge_status(service: DetectionKnowledgeService) -> ServiceStatus:
    try:
        stats = service.stats()
    except Exception:  # a status check must never raise or leak internals
        return ServiceStatus(
            name="detection_knowledge",
            display_name="Detection Knowledge Library",
            status=ServiceState.DEGRADED,
            detail="Library status could not be read.",
        )
    healthy = stats.total_rules > 0
    return ServiceStatus(
        name="detection_knowledge",
        display_name="Detection Knowledge Library",
        status=ServiceState.HEALTHY if healthy else ServiceState.DEGRADED,
        detail=f"{stats.total_rules} rule(s) indexed from {stats.sources} source(s).",
    )


def _rollup(states: Iterable[ServiceState]) -> ServiceState:
    values = list(states)
    if any(s == ServiceState.OFFLINE for s in values):
        return ServiceState.OFFLINE
    if any(s == ServiceState.DEGRADED for s in values):
        return ServiceState.DEGRADED
    return ServiceState.HEALTHY
