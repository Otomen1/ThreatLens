"""Investigation Correlation Engine (Phase 7.0 — framework only).

A pure, deterministic engine that consumes a completed
:class:`~threatlens.reasoning.models.InvestigationSummary` and combines its
*existing* findings into higher-level
:class:`~threatlens.correlation.models.CorrelationObservation` objects — before
those richer observations are consumed by higher-level reasoning. It never
invents evidence, never scores, and never produces confidence, severity,
priority, or recommendations (those remain the Reasoning Engine's job). Every
observation references the source findings it combines, so every correlation is
fully explainable. No AI, no machine learning, no probabilistic inference.

Phase 7.0 ships the engine — models, rule model, a single generic evaluator, a
rule registry, the service, the summary — with a small **seed rule set** (12
declarative rules) so the whole pipeline is exercised end-to-end. Rule
expansion is an explicit later phase (7.1). The engine consumes ``reasoning``'s
frozen output and is consumed only by later phases; nothing in the frozen
subsystems imports from here.
"""

from __future__ import annotations

from .engine import (
    CORRELATION_FRAMEWORK_VERSION,
    compute_observation_id,
    correlate,
    evaluate_rule,
)
from .exceptions import (
    CorrelationConfigurationError,
    CorrelationError,
    DuplicateCorrelationRuleError,
)
from .models import (
    CorrelationCategory,
    CorrelationEvidence,
    CorrelationMatch,
    CorrelationMetadata,
    CorrelationObservation,
    CorrelationRelationship,
    CorrelationRelationshipType,
    CorrelationRule,
    CorrelationStatistics,
    CorrelationSummary,
)
from .registry import CorrelationRegistry, build_default_registry
from .rules import SEED_RULES, default_rules
from .service import CorrelationService
from .summary import build_correlation_summary, compute_summary_id

__all__ = [
    "CORRELATION_FRAMEWORK_VERSION",
    "SEED_RULES",
    "CorrelationCategory",
    "CorrelationConfigurationError",
    "CorrelationError",
    "CorrelationEvidence",
    "CorrelationMatch",
    "CorrelationMetadata",
    "CorrelationObservation",
    "CorrelationRegistry",
    "CorrelationRelationship",
    "CorrelationRelationshipType",
    "CorrelationRule",
    "CorrelationService",
    "CorrelationStatistics",
    "CorrelationSummary",
    "DuplicateCorrelationRuleError",
    "build_correlation_summary",
    "build_default_registry",
    "compute_observation_id",
    "compute_summary_id",
    "correlate",
    "default_rules",
    "evaluate_rule",
]
