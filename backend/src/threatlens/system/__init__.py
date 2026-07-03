"""The Operational Dashboard (v1): system health, API consumption, configuration.

Strictly downstream and read-only observability for administrators and
developers. This package never influences — and is never imported by — the
Investigation Engine, the Reasoning Engine, the Detection Engine, the
Detection Knowledge Library, or the AI service; it only reads their already-
computed, public outputs and existing configuration checks. See
``docs/architecture/PHASE-OPERATIONAL-DASHBOARD-V1.md``.
"""

from __future__ import annotations

from .metrics import MetricsRegistry, registry
from .router import build_system_router
from .schemas import (
    AIConfigStatus,
    AIUsage,
    ConfigItem,
    ConfigStatusResponse,
    DetectionEngineeringUsage,
    DetectionKnowledgeUsage,
    InvestigationUsage,
    KnowledgeProviderUsage,
    ProviderUsage,
    ServiceState,
    ServiceStatus,
    SystemHealthResponse,
    UsageResponse,
)

__all__ = [
    "AIConfigStatus",
    "AIUsage",
    "ConfigItem",
    "ConfigStatusResponse",
    "DetectionEngineeringUsage",
    "DetectionKnowledgeUsage",
    "InvestigationUsage",
    "KnowledgeProviderUsage",
    "MetricsRegistry",
    "ProviderUsage",
    "ServiceState",
    "ServiceStatus",
    "SystemHealthResponse",
    "UsageResponse",
    "build_system_router",
    "registry",
]
