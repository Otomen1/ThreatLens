"""The reasoning entry point — assembles evidence, generates findings, summarizes.

``reason()`` is the pure, deterministic public contract of the Investigation
Intelligence Engine. As of Phase 3.1b it:

1. assembles the weighted evidence ledger (EvidenceAssembler),
2. generates findings via the FindingEngine (typed rules + merge + per-finding
   confidence from the unchanged ConfidenceScorer),
3. derives the overall posture and headline confidence,

and returns an InvestigationSummary. Recommendations remain empty until 3.1c;
InvestigationContext-aware priority arrives in 3.1d.

Determinism: for identical inputs *and* an identical ``now``, the output is
identical. ``now`` is injectable so tests are fully reproducible.
"""

from __future__ import annotations

from datetime import UTC, datetime

from ..entities.models import Entity
from ..providers.aggregation import AggregatedResult
from .confidence import ConfidenceScorer
from .evidence import EvidenceAssembler
from .findings import FindingEngine, overall_posture
from .models import FindingCategory, InvestigationSummary
from .registry import build_default_rule_registry

ENGINE_VERSION = "3.1b"


def reason(
    entity: Entity,
    ti: AggregatedResult,
    knowledge: AggregatedResult,
    *,
    now: datetime | None = None,
) -> InvestigationSummary:
    """Reason over aggregated intelligence and return an InvestigationSummary."""
    moment = now or datetime.now(UTC)
    ledger = EvidenceAssembler().assemble(ti, knowledge, now=moment)
    findings = FindingEngine(build_default_rule_registry()).generate(entity, ledger, now=moment)

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
        recommendations=[],  # 3.1c
        engine_version=ENGINE_VERSION,
        generated_at=moment,
    )
