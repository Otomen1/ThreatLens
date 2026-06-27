"""The reasoning entry point — assembles evidence and scores overall confidence.

``reason()`` is the pure, deterministic public contract of the Investigation
Intelligence Engine. In Phase 3.1a it runs the evidence foundation only:
assemble the ledger, then derive an overall confidence from it. Finding
generation, recommendations, and InvestigationContext-aware priority arrive in
later slices (3.1b–3.1d); until then ``findings`` and ``recommendations`` are
empty and ``posture`` is INFORMATIONAL.

Determinism: for identical inputs *and* an identical ``now``, the output is
identical. ``now`` is injectable so tests are fully reproducible.
"""

from __future__ import annotations

from datetime import UTC, datetime

from ..entities.models import Entity
from ..providers.aggregation import AggregatedResult
from .confidence import ConfidenceScorer
from .evidence import EvidenceAssembler
from .models import InvestigationSummary, Severity

ENGINE_VERSION = "3.1a"


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
    overall_confidence = ConfidenceScorer().score(ledger.evidence, now=moment)
    return InvestigationSummary(
        entity_type=entity.type,
        entity_value=entity.value,
        posture=Severity.INFORMATIONAL,  # no findings yet (3.1b)
        overall_confidence=overall_confidence,
        categories=frozenset(),
        findings=[],
        recommendations=[],
        engine_version=ENGINE_VERSION,
        generated_at=moment,
    )
