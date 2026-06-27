"""The Investigation Intelligence Engine — deterministic reasoning over intelligence.

Phase 3.1a establishes the canonical models and the evidence foundation
(EvidenceAssembler + ConfidenceScorer) behind one pure entry point, :func:`reason`.
Rule-driven findings, recommendations, and context-aware priority arrive in later
slices. AI is strictly downstream and never part of this package.
"""

from __future__ import annotations

from .confidence import ConfidenceScorer
from .engine import ENGINE_VERSION, reason
from .evidence import EvidenceAssembler, EvidenceLedger
from .models import (
    Confidence,
    ConfidenceBand,
    ConfidenceFactor,
    EvidenceDimension,
    EvidencePolarity,
    Finding,
    FindingCategory,
    InvestigationSummary,
    Recommendation,
    RecommendationAction,
    RecommendationCategory,
    Severity,
    WeightedEvidence,
)

__all__ = [
    "ENGINE_VERSION",
    "Confidence",
    "ConfidenceBand",
    "ConfidenceFactor",
    "ConfidenceScorer",
    "EvidenceAssembler",
    "EvidenceDimension",
    "EvidenceLedger",
    "EvidencePolarity",
    "Finding",
    "FindingCategory",
    "InvestigationSummary",
    "Recommendation",
    "RecommendationAction",
    "RecommendationCategory",
    "Severity",
    "WeightedEvidence",
    "reason",
]
