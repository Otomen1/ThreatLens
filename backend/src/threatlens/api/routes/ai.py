"""AI explanation route: downstream, optional narration of a completed investigation."""

from __future__ import annotations

import time
from typing import Annotated

from fastapi import APIRouter, Depends

from ...ai import AIExplanation, AIExplanationService, build_ai_service
from ...reasoning import InvestigationSummary
from ...system import registry as metrics_registry
from ...system.record import record_ai_explanation
from ..timing import elapsed_ms

router = APIRouter()

# The AI explanation service is downstream and optional; built once from the
# environment. It is disabled by default, so ThreatLens behaves identically when
# no AI provider is configured or running.
_ai_service = build_ai_service()


def get_ai_service() -> AIExplanationService:
    """Provide the AI explanation service (overridable in tests)."""
    return _ai_service


@router.post("/api/v1/explain", response_model=AIExplanation)
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
    _duration_ms = elapsed_ms(_start)
    if explanation.status != "disabled":
        record_ai_explanation(
            metrics_registry,
            explanation=explanation,
            prompt_chars=len(summary.model_dump_json()),
            duration_ms=_duration_ms,
        )
    return explanation
