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
from .findings import FindingEngine, compute_finding_id, overall_posture
from .models import (
    EMPTY_CONTEXT,
    AssetCriticality,
    Confidence,
    ConfidenceBand,
    ConfidenceFactor,
    Environment,
    EvidenceDimension,
    EvidencePolarity,
    Finding,
    FindingCategory,
    InvestigationContext,
    InvestigationSummary,
    Recommendation,
    RecommendationAction,
    RecommendationCategory,
    Severity,
    WeightedEvidence,
)
from .priority import derive_finding_priority
from .recommendations import (
    DEFAULT_RECOMMENDATION_RULES,
    DuplicateRecommendationRuleError,
    RecommendationEngine,
    RecommendationRegistry,
    RecommendationRule,
    build_default_recommendation_registry,
)
from .registry import DuplicateRuleError, RuleRegistry, build_default_rule_registry
from .rules import DEFAULT_FINDING_RULES, FindingDraft, FindingRule, RuleContext

__all__ = [
    "DEFAULT_FINDING_RULES",
    "DEFAULT_RECOMMENDATION_RULES",
    "EMPTY_CONTEXT",
    "ENGINE_VERSION",
    "AssetCriticality",
    "Confidence",
    "ConfidenceBand",
    "ConfidenceFactor",
    "ConfidenceScorer",
    "DuplicateRecommendationRuleError",
    "DuplicateRuleError",
    "Environment",
    "EvidenceAssembler",
    "EvidenceDimension",
    "EvidenceLedger",
    "EvidencePolarity",
    "Finding",
    "FindingCategory",
    "FindingDraft",
    "FindingEngine",
    "FindingRule",
    "InvestigationContext",
    "InvestigationSummary",
    "Recommendation",
    "RecommendationAction",
    "RecommendationCategory",
    "RecommendationEngine",
    "RecommendationRegistry",
    "RecommendationRule",
    "RuleContext",
    "RuleRegistry",
    "Severity",
    "WeightedEvidence",
    "build_default_recommendation_registry",
    "build_default_rule_registry",
    "compute_finding_id",
    "derive_finding_priority",
    "overall_posture",
    "reason",
]
