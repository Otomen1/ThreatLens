"""Performance benchmark for the deterministic reasoning pipeline (Phase 3.15).

Measures each stage of an investigation in isolation plus the end-to-end
deterministic path, on a representative heavy input (a malicious IP that drops
malware, is attributed to an actor, and uses a technique → four findings). It is
offline and CPU-only; outbound provider I/O is explicitly out of scope (it is
network-bound and measured at the provider layer, not here).

Run the full report::

    python tests/benchmark/perf.py            # or: python -m tests.benchmark.perf

The numbers are reported as per-call latency; the suite is exercised (without
timing assertions) by ``test_perf_smoke.py`` so it cannot bit-rot in CI.
"""

from __future__ import annotations

import statistics
from collections.abc import Callable
from datetime import UTC, datetime
from time import perf_counter

from threatlens.entities.models import Entity
from threatlens.entities.types import EntityType, ValidationStatus
from threatlens.providers import build_default_router
from threatlens.providers.aggregation import (
    AggregatedResult,
    AttributedEvidence,
    AttributedRelationship,
    ProviderSummary,
    aggregate,
)
from threatlens.providers.results import (
    Evidence,
    EvidenceType,
    IntelligenceResult,
    Relationship,
    RelationshipTargetType,
    RelationshipType,
    Reputation,
    ReputationLevel,
    ResultStatus,
)
from threatlens.reasoning import ConfidenceScorer, reason
from threatlens.reasoning.evidence import EvidenceAssembler
from threatlens.reasoning.findings import FindingEngine
from threatlens.reasoning.recommendations import (
    RecommendationEngine,
    build_default_recommendation_registry,
)
from threatlens.reasoning.registry import build_default_rule_registry
from threatlens.reference import build_default_reference_router

_NOW = datetime(2025, 1, 1, tzinfo=UTC)


# --------------------------------------------------------------------------- #
# Representative heavy input (four findings)
# --------------------------------------------------------------------------- #


def _entity() -> Entity:
    return Entity(
        type=EntityType.IPV4,
        value="185.220.101.1",
        normalized_value="185.220.101.1",
        confidence=100,
        validation=ValidationStatus.VALID,
        possible_matches=[],
    )


def _ti() -> AggregatedResult:
    return AggregatedResult(
        entity_type=EntityType.IPV4,
        entity_value="185.220.101.1",
        providers=[
            ProviderSummary(
                provider="abuseipdb",
                status=ResultStatus.OK,
                reputation=Reputation(level=ReputationLevel.MALICIOUS, score=100),
            ),
            ProviderSummary(
                provider="otx",
                status=ResultStatus.OK,
                reputation=Reputation(level=ReputationLevel.SUSPICIOUS, score=60),
            ),
        ],
        evidence=[
            AttributedEvidence(
                evidence=Evidence(
                    type=EvidenceType.ABUSE_CONFIDENCE,
                    summary="Abuse confidence score: 100%",
                    value="100%",
                    observed_at=_NOW,
                ),
                sources=["abuseipdb"],
            ),
            AttributedEvidence(
                evidence=Evidence(
                    type=EvidenceType.PULSE_MATCH, summary="OTX pulse: APT", value="apt"
                ),
                sources=["otx"],
            ),
        ],
        relationships=[
            AttributedRelationship(
                relationship=Relationship(
                    relationship=RelationshipType.INDICATES,
                    target_type=RelationshipTargetType.MALWARE_FAMILY,
                    target_value="Cobalt Strike",
                ),
                sources=["otx"],
            ),
            AttributedRelationship(
                relationship=Relationship(
                    relationship=RelationshipType.ATTRIBUTED_TO,
                    target_type=RelationshipTargetType.THREAT_ACTOR,
                    target_value="APT29",
                ),
                sources=["otx"],
            ),
            AttributedRelationship(
                relationship=Relationship(
                    relationship=RelationshipType.USES,
                    target_type=RelationshipTargetType.ATTACK_PATTERN,
                    target_value="T1071",
                ),
                sources=["otx"],
            ),
        ],
    )


def _knowledge() -> AggregatedResult:
    return AggregatedResult(entity_type=EntityType.IPV4, entity_value="185.220.101.1")


def _provider_results() -> list[IntelligenceResult]:
    """A handful of per-provider results to feed the aggregation stage."""
    return [
        IntelligenceResult(
            provider=name,
            entity_type=EntityType.IPV4,
            entity_value="185.220.101.1",
            status=ResultStatus.OK,
            reputation=Reputation(level=ReputationLevel.MALICIOUS, score=90),
            evidence=[
                Evidence(type=EvidenceType.DETECTION, summary=f"detection from {name}", value=name)
            ],
        )
        for name in ("abuseipdb", "otx", "urlhaus")
    ]


# --------------------------------------------------------------------------- #
# Timing
# --------------------------------------------------------------------------- #


def _bench(fn: Callable[[], object], iterations: int) -> dict[str, float]:
    for _ in range(min(50, iterations)):  # warm up
        fn()
    samples = []
    for _ in range(iterations):
        start = perf_counter()
        fn()
        samples.append((perf_counter() - start) * 1e6)  # microseconds
    samples.sort()
    p95 = samples[min(len(samples) - 1, int(len(samples) * 0.95))]
    return {
        "mean_us": statistics.fmean(samples),
        "median_us": statistics.median(samples),
        "p95_us": p95,
        "iterations": float(iterations),
    }


def measure_all(iterations: int = 2000) -> dict[str, dict[str, float]]:
    """Measure each pipeline stage and the end-to-end deterministic path."""
    entity = _entity()
    ti, knowledge = _ti(), _knowledge()
    results = _provider_results()

    ti_router = build_default_router()
    ref_router = build_default_reference_router()
    assembler = EvidenceAssembler()
    scorer = ConfidenceScorer()
    finding_engine = FindingEngine(build_default_rule_registry())
    rec_engine = RecommendationEngine(build_default_recommendation_registry())

    ledger = assembler.assemble(ti, knowledge, now=_NOW)
    findings = finding_engine.generate(entity, ledger, now=_NOW)

    stages: dict[str, Callable[[], object]] = {
        "entity_detection": lambda: _detect("185.220.101.1"),
        "provider_routing_ti": lambda: ti_router.route(entity),
        "provider_routing_reference": lambda: ref_router.route(entity),
        "aggregation": lambda: aggregate(
            results, entity_type=EntityType.IPV4, entity_value="185.220.101.1"
        ),
        "evidence_assembly": lambda: assembler.assemble(ti, knowledge, now=_NOW),
        "confidence_scoring": lambda: scorer.score(ledger.evidence, now=_NOW),
        "finding_generation": lambda: finding_engine.generate(entity, ledger, now=_NOW),
        "recommendation_rollup": lambda: rec_engine.rollup(findings),
        "reason_end_to_end": lambda: reason(entity, ti, knowledge, now=_NOW),
    }
    return {label: _bench(fn, iterations) for label, fn in stages.items()}


def _detect(query: str) -> object:
    # Imported lazily so the timing of the import is not attributed to detection.
    from threatlens.search import detect

    return detect(query)


def main() -> None:
    results = measure_all()
    width = max(len(label) for label in results)
    print(f"{'stage':<{width}}  {'median':>10}  {'mean':>10}  {'p95':>10}")
    print("-" * (width + 36))
    for label, stats in results.items():
        print(
            f"{label:<{width}}  "
            f"{stats['median_us']:>8.1f}us  "
            f"{stats['mean_us']:>8.1f}us  "
            f"{stats['p95_us']:>8.1f}us"
        )


if __name__ == "__main__":
    main()
