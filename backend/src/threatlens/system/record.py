"""Bridges existing API responses to the metrics registry (Section 2 wiring).

Each function takes an object ``api/app.py``'s existing route logic *already*
computed and returned, and records it into :class:`~.metrics.MetricsRegistry`.
None of these functions can influence the object they read — they run after
the real result is already final — and none are called from anywhere but
``api/app.py``, immediately after the unchanged route logic completes.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .metrics import MetricsRegistry

if TYPE_CHECKING:
    from ..ai.models import AIExplanation
    from ..detection.models import DetectionPackage
    from ..providers.aggregation import AggregatedResult
    from ..reasoning import InvestigationSummary

# A provider that responded (even "no record found") is a successful call;
# only genuine outages/errors count against it.
_SUCCESS_STATUSES = frozenset({"ok", "not_found", "partial"})


def record_investigation(
    registry: MetricsRegistry,
    *,
    threat_intelligence: AggregatedResult,
    knowledge: AggregatedResult,
    summary: InvestigationSummary,
    duration_ms: float,
) -> None:
    """Record one completed ``/investigate`` call.

    Per-provider latency is the enclosing investigation's wall-clock time
    (providers run concurrently — see :meth:`.metrics.MetricsRegistry.record_ti`).
    """
    for item in threat_intelligence.providers:
        registry.record_ti(
            item.provider, success=item.status in _SUCCESS_STATUSES, latency_ms=duration_ms
        )
    for item in knowledge.providers:
        registry.record_kb(
            item.provider, success=item.status in _SUCCESS_STATUSES, latency_ms=duration_ms
        )
    registry.record_investigation(
        duration_ms=duration_ms,
        findings=len(summary.findings),
        recommendations=len(summary.recommendations),
        confidence=float(summary.overall_confidence.score) if summary.overall_confidence else None,
    )


def record_ai_explanation(
    registry: MetricsRegistry,
    *,
    explanation: AIExplanation,
    prompt_chars: int,
    duration_ms: float,
) -> None:
    """Record one completed ``/explain`` call (the caller skips this when disabled)."""
    completion_chars = (
        len(explanation.executive_summary)
        + len(explanation.technical_summary)
        + sum(len(f.explanation) for f in explanation.finding_explanations)
        + sum(len(r.explanation) for r in explanation.recommendation_explanations)
    )
    registry.record_ai(
        success=explanation.status == "ok",
        latency_ms=duration_ms,
        prompt_chars=prompt_chars,
        completion_chars=completion_chars,
    )


def record_detection_generation(
    registry: MetricsRegistry, *, package: DetectionPackage, duration_ms: float
) -> None:
    """Record one completed ``/detections`` call."""
    registry.record_detection_generation(
        languages=[artifact.language.value for artifact in package.artifacts],
        latency_ms=duration_ms,
    )


def record_dkl_query(
    registry: MetricsRegistry, *, duration_ms: float, success: bool = True
) -> None:
    """Record one completed Detection Knowledge Library query (recommend/search)."""
    registry.record_dkl_query(success=success, latency_ms=duration_ms)
