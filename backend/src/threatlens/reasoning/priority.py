"""Derived priority — the single source of truth for urgency (Phase 3.1d).

Finding priority is derived deterministically from the finding's own severity and
confidence plus the optional :class:`InvestigationContext`. Context may *only*
increase urgency (lower the number); it never changes severity, confidence,
evidence, findings, or recommendations.

Because context describes the investigated asset, it is uniform across all
findings in one investigation: it shifts their absolute priority (useful for
ranking a queue of investigations) without reordering findings *within* one
investigation. Recommendation priority inherits the finding priority (see
:mod:`.recommendations`) — there is no second priority algorithm.
"""

from __future__ import annotations

from .models import (
    AssetCriticality,
    Confidence,
    ConfidenceBand,
    Environment,
    InvestigationContext,
    Severity,
)

# Confidence band ordering (insufficient … very high).
_BAND_ORDER: tuple[ConfidenceBand, ...] = (
    ConfidenceBand.INSUFFICIENT,
    ConfidenceBand.LOW,
    ConfidenceBand.MODERATE,
    ConfidenceBand.HIGH,
    ConfidenceBand.VERY_HIGH,
)


def band_rank(band: ConfidenceBand) -> int:
    """Ordinal rank of a confidence band (0 = insufficient, 4 = very high)."""
    return _BAND_ORDER.index(band)


# Context urgency boosts (all >= 0 — context only increases urgency).
_CRITICALITY_BOOST: dict[AssetCriticality, int] = {
    AssetCriticality.UNKNOWN: 0,
    AssetCriticality.LOW: 0,
    AssetCriticality.MEDIUM: 10,
    AssetCriticality.HIGH: 25,
    AssetCriticality.CRITICAL: 40,
}
_ENVIRONMENT_BOOST: dict[Environment, int] = {
    Environment.UNKNOWN: 0,
    Environment.DEVELOPMENT: 0,
    Environment.TEST: 0,
    Environment.STAGING: 10,
    Environment.PRODUCTION: 20,
}
_INTERNET_FACING_BOOST = 20


def context_boost(context: InvestigationContext) -> int:
    """Total non-negative urgency boost from the investigation context."""
    return (
        _CRITICALITY_BOOST[context.criticality]
        + _ENVIRONMENT_BOOST[context.environment]
        + (_INTERNET_FACING_BOOST if context.internet_facing else 0)
    )


def derive_finding_priority(
    severity: Severity, confidence: Confidence, context: InvestigationContext
) -> int:
    """Deterministic finding priority (0 = most urgent).

    Severity dominates (bands of 100); confidence refines within a band (0–40);
    context subtracts a bounded, non-negative boost. Clamped to >= 0.
    """
    severity_base = (int(Severity.CRITICAL) - int(severity)) * 100
    confidence_penalty = (band_rank(ConfidenceBand.VERY_HIGH) - band_rank(confidence.band)) * 10
    return max(0, severity_base + confidence_penalty - context_boost(context))
