"""Investigation Correlation Engine route: a pure framework-readiness probe (Phase 7.0)."""

from __future__ import annotations

from fastapi import APIRouter

from ...correlation import CORRELATION_FRAMEWORK_VERSION
from ...correlation import build_default_registry as build_correlation_registry
from ..schemas import CorrelationFrameworkStatus

router = APIRouter()

# Investigation Correlation Engine: a pure, deterministic engine that combines a
# completed investigation's existing findings into higher-level correlation
# observations (referencing source findings, never inventing evidence). Phase
# 7.0 is framework-only — a small seed rule set, no /investigate integration.
# See docs/architecture/PHASE-7.0-CORRELATION-FRAMEWORK.md.
_correlation_registry = build_correlation_registry()


@router.get("/api/v1/correlation", response_model=CorrelationFrameworkStatus)
def correlation_framework_status() -> CorrelationFrameworkStatus:
    """Report Investigation Correlation Engine status (Phase 7.0 — framework only).

    A pure readiness probe: framework version and the count of registered
    correlation rules. Never runs a correlation (that consumes an
    ``InvestigationSummary``) and never touches the network — it only reads the
    seeded rule registry's length. Not integrated into ``/investigate`` yet.
    """
    count = len(_correlation_registry)
    return CorrelationFrameworkStatus(
        status="ready",
        message="No rules registered" if count == 0 else f"{count} correlation rule(s) registered",
        framework_version=CORRELATION_FRAMEWORK_VERSION,
        rules_registered=count,
    )
