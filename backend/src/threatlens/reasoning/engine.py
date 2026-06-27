"""The reasoning entry point — assembles evidence, generates findings, summarizes.

``reason()`` is the pure, deterministic public contract of the Investigation
Intelligence Engine. As of Phase 3.1d it:

1. assembles the weighted evidence ledger (EvidenceAssembler),
2. generates findings via the FindingEngine (typed rules + merge + per-finding
   confidence from the unchanged ConfidenceScorer),
3. derives each finding's priority from its severity/confidence and the optional
   InvestigationContext (context affects priority only — never severity,
   confidence, evidence, findings, or recommendation content),
4. attaches finding-owned recommendations (RecommendationEngine, findings only),
5. derives the overall posture, headline confidence, and the recommendation rollup,

and returns an InvestigationSummary.

Determinism: for identical inputs (including ``context`` and ``now``), the output
is identical. ``context`` defaults to EMPTY, so existing callers are unaffected.
"""

from __future__ import annotations

from datetime import UTC, datetime

from ..entities.models import Entity
from ..providers.aggregation import AggregatedResult
from .confidence import ConfidenceScorer
from .evidence import EvidenceAssembler
from .findings import FindingEngine, overall_posture
from .models import EMPTY_CONTEXT, FindingCategory, InvestigationContext, InvestigationSummary
from .priority import derive_finding_priority
from .recommendations import RecommendationEngine, build_default_recommendation_registry
from .registry import build_default_rule_registry

ENGINE_VERSION = "3.1d"


def reason(
    entity: Entity,
    ti: AggregatedResult,
    knowledge: AggregatedResult,
    *,
    context: InvestigationContext = EMPTY_CONTEXT,
    now: datetime | None = None,
) -> InvestigationSummary:
    """Reason over aggregated intelligence and return an InvestigationSummary."""
    moment = now or datetime.now(UTC)
    ledger = EvidenceAssembler().assemble(ti, knowledge, now=moment)
    findings = FindingEngine(build_default_rule_registry()).generate(entity, ledger, now=moment)

    # Derive priority from severity/confidence + context (context affects priority only).
    findings = [
        finding.model_copy(
            update={
                "priority": derive_finding_priority(finding.severity, finding.confidence, context)
            }
        )
        for finding in findings
    ]

    # Attach finding-owned recommendations (they inherit the derived priority).
    rec_engine = RecommendationEngine(build_default_recommendation_registry())
    findings = [
        finding.model_copy(update={"recommendations": rec_engine.for_finding(finding)})
        for finding in findings
    ]

    if findings:
        # Findings are sorted worst-first; the headline finding drives confidence.
        overall_confidence = findings[0].confidence
        categories: frozenset[FindingCategory] = frozenset(
            cat for finding in findings for cat in finding.categories
        )
    else:
        # No finding fired — fall back to the evidence-level confidence (3.1a behaviour).
        overall_confidence = ConfidenceScorer().score(ledger.evidence, now=moment)
        categories = frozenset()

    return InvestigationSummary(
        entity_type=entity.type,
        entity_value=entity.value,
        posture=overall_posture(findings),
        overall_confidence=overall_confidence,
        categories=categories,
        findings=findings,
        recommendations=rec_engine.rollup(findings),
        engine_version=ENGINE_VERSION,
        generated_at=moment,
    )
