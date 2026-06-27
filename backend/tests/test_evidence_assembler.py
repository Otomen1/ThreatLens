"""Tests for the EvidenceAssembler (Phase 3.1a).

The assembler is a pure normalization layer: it must preserve attribution,
timestamps, relationships and references, lift reputations, assign deterministic
weight/polarity/dimension, and produce identical output for identical input.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from threatlens.entities.types import EntityType
from threatlens.providers.aggregation import (
    AggregatedResult,
    AttributedEvidence,
    AttributedReference,
    AttributedRelationship,
    ProviderSummary,
)
from threatlens.providers.results import (
    Evidence,
    EvidenceType,
    Reference,
    Relationship,
    RelationshipTargetType,
    RelationshipType,
    Reputation,
    ReputationLevel,
    ResultStatus,
)
from threatlens.reasoning import EvidenceDimension, EvidencePolarity
from threatlens.reasoning.evidence import EvidenceAssembler

NOW = datetime(2024, 6, 1, tzinfo=UTC)


def _attr_ev(
    etype: EvidenceType,
    *,
    value: str = "v",
    sources: list[str] | None = None,
    observed_at: datetime | None = None,
) -> AttributedEvidence:
    return AttributedEvidence(
        evidence=Evidence(
            type=etype, summary=f"{etype.value} summary", value=value, observed_at=observed_at
        ),
        sources=sources or ["abuseipdb"],
    )


def _agg(
    *,
    entity_type: EntityType = EntityType.IPV4,
    entity_value: str = "1.2.3.4",
    evidence: list[AttributedEvidence] | None = None,
    providers: list[ProviderSummary] | None = None,
    relationships: list[AttributedRelationship] | None = None,
    references: list[AttributedReference] | None = None,
) -> AggregatedResult:
    return AggregatedResult(
        entity_type=entity_type,
        entity_value=entity_value,
        providers=providers or [],
        evidence=evidence or [],
        relationships=relationships or [],
        references=references or [],
    )


def _empty(entity_type: EntityType = EntityType.IPV4) -> AggregatedResult:
    return _agg(entity_type=entity_type)


# --------------------------------------------------------------------------- #


class TestEmptyAndShape:
    def test_empty_inputs_produce_empty_ledger(self) -> None:
        ledger = EvidenceAssembler().assemble(_empty(), _empty(), now=NOW)
        assert ledger.evidence == ()
        assert ledger.relationships == ()
        assert ledger.references == ()

    def test_evidence_combined_from_both_frameworks(self) -> None:
        ti = _agg(evidence=[_attr_ev(EvidenceType.DETECTION)])
        kb = _agg(evidence=[_attr_ev(EvidenceType.CLASSIFICATION)])
        ledger = EvidenceAssembler().assemble(ti, kb, now=NOW)
        assert len(ledger.evidence) == 2


class TestPreservation:
    def test_attribution_preserved(self) -> None:
        ti = _agg(evidence=[_attr_ev(EvidenceType.DETECTION, sources=["abuseipdb", "otx"])])
        ledger = EvidenceAssembler().assemble(ti, _empty(), now=NOW)
        assert ledger.evidence[0].evidence.sources == ["abuseipdb", "otx"]

    def test_timestamp_preserved(self) -> None:
        seen = datetime(2024, 5, 1, tzinfo=UTC)
        ti = _agg(evidence=[_attr_ev(EvidenceType.DETECTION, observed_at=seen)])
        ledger = EvidenceAssembler().assemble(ti, _empty(), now=NOW)
        assert ledger.evidence[0].evidence.evidence.observed_at == seen

    def test_relationships_preserved(self) -> None:
        rel = AttributedRelationship(
            relationship=Relationship(
                relationship=RelationshipType.RELATED_TO,
                target_type=RelationshipTargetType.WEAKNESS,
                target_value="CWE-79",
            ),
            sources=["nvd"],
        )
        kb = _agg(relationships=[rel])
        ledger = EvidenceAssembler().assemble(_empty(), kb, now=NOW)
        assert ledger.relationships == (rel,)

    def test_references_preserved(self) -> None:
        ref = AttributedReference(
            reference=Reference(title="t", url="https://example.com"),
            sources=["nvd"],
        )
        kb = _agg(references=[ref])
        ledger = EvidenceAssembler().assemble(_empty(), kb, now=NOW)
        assert ledger.references == (ref,)


class TestWeightingAndClassification:
    def test_dimension_mapping(self) -> None:
        ti = _agg(evidence=[_attr_ev(EvidenceType.DETECTION)])
        ledger = EvidenceAssembler().assemble(ti, _empty(), now=NOW)
        assert ledger.evidence[0].dimension is EvidenceDimension.REPUTATION

    def test_supporting_polarity_for_detection(self) -> None:
        ti = _agg(evidence=[_attr_ev(EvidenceType.DETECTION)])
        ledger = EvidenceAssembler().assemble(ti, _empty(), now=NOW)
        assert ledger.evidence[0].polarity is EvidencePolarity.SUPPORTING

    def test_contextual_polarity_for_classification(self) -> None:
        kb = _agg(evidence=[_attr_ev(EvidenceType.CLASSIFICATION)])
        ledger = EvidenceAssembler().assemble(_empty(), kb, now=NOW)
        assert ledger.evidence[0].polarity is EvidencePolarity.CONTEXTUAL

    def test_weight_combines_base_authority_freshness(self) -> None:
        # BLOCKLIST base 1.0 × abuseipdb authority 0.60 × freshness 1.0 (undated) = 0.60
        ti = _agg(evidence=[_attr_ev(EvidenceType.BLOCKLIST, sources=["abuseipdb"])])
        ledger = EvidenceAssembler().assemble(ti, _empty(), now=NOW)
        assert ledger.evidence[0].weight == 0.6

    def test_unknown_provider_default_authority(self) -> None:
        # DETECTION base 0.9 × unknown authority 0.40 × fresh 1.0 = 0.36
        ti = _agg(evidence=[_attr_ev(EvidenceType.DETECTION, sources=["mystery"])])
        ledger = EvidenceAssembler().assemble(ti, _empty(), now=NOW)
        assert abs(ledger.evidence[0].weight - 0.36) < 1e-9

    def test_stale_evidence_decays_weight(self) -> None:
        old = NOW - timedelta(days=400)
        ti = _agg(
            evidence=[_attr_ev(EvidenceType.BLOCKLIST, sources=["abuseipdb"], observed_at=old)]
        )
        ledger = EvidenceAssembler().assemble(ti, _empty(), now=NOW)
        # 1.0 × 0.60 × 0.30 (floor) = 0.18
        assert abs(ledger.evidence[0].weight - 0.18) < 1e-9


class TestReputationLifting:
    def test_malicious_reputation_supporting(self) -> None:
        ps = ProviderSummary(
            provider="abuseipdb",
            status=ResultStatus.OK,
            reputation=Reputation(level=ReputationLevel.MALICIOUS, score=90),
        )
        ti = _agg(providers=[ps])
        ledger = EvidenceAssembler().assemble(ti, _empty(), now=NOW)
        assert len(ledger.evidence) == 1
        we = ledger.evidence[0]
        assert we.polarity is EvidencePolarity.SUPPORTING
        assert we.dimension is EvidenceDimension.REPUTATION
        assert we.evidence.sources == ["abuseipdb"]
        # 1.0 (malicious) × 0.60 (abuseipdb) = 0.60
        assert we.weight == 0.6

    def test_benign_reputation_contradicting(self) -> None:
        ps = ProviderSummary(
            provider="otx",
            status=ResultStatus.OK,
            reputation=Reputation(level=ReputationLevel.BENIGN),
        )
        ledger = EvidenceAssembler().assemble(_agg(providers=[ps]), _empty(), now=NOW)
        assert ledger.evidence[0].polarity is EvidencePolarity.CONTRADICTING

    def test_unknown_reputation_skipped(self) -> None:
        ps = ProviderSummary(
            provider="otx",
            status=ResultStatus.OK,
            reputation=Reputation(level=ReputationLevel.UNKNOWN),
        )
        ledger = EvidenceAssembler().assemble(_agg(providers=[ps]), _empty(), now=NOW)
        assert ledger.evidence == ()

    def test_provider_without_reputation_skipped(self) -> None:
        ps = ProviderSummary(provider="nvd", status=ResultStatus.OK, reputation=None)
        ledger = EvidenceAssembler().assemble(_empty(), _agg(providers=[ps]), now=NOW)
        assert ledger.evidence == ()


class TestDeterminism:
    def test_identical_inputs_identical_output(self) -> None:
        ti = _agg(
            evidence=[_attr_ev(EvidenceType.DETECTION), _attr_ev(EvidenceType.ABUSE_CONFIDENCE)],
            providers=[
                ProviderSummary(
                    provider="abuseipdb",
                    status=ResultStatus.OK,
                    reputation=Reputation(level=ReputationLevel.MALICIOUS),
                )
            ],
        )
        a = EvidenceAssembler().assemble(ti, _empty(), now=NOW)
        b = EvidenceAssembler().assemble(ti, _empty(), now=NOW)
        assert a == b
