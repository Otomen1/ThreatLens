"""Unit tests for the Intelligence Aggregation Engine (Phase 1.4).

Pure, offline merging of per-provider results into one canonical aggregate:
attribution, de-duplication across providers, and graceful partial failure. No
providers, no network, no scoring.
"""

from __future__ import annotations

from collections.abc import Sequence

from threatlens.entities.types import EntityType
from threatlens.providers import (
    Evidence,
    EvidenceType,
    IntelligenceResult,
    Reference,
    Relationship,
    RelationshipTargetType,
    RelationshipType,
    Reputation,
    ReputationLevel,
    ResultStatus,
    aggregate,
)

_ENTITY_TYPE = EntityType.SHA256
_ENTITY_VALUE = "a" * 64


def make_result(
    provider: str,
    *,
    status: ResultStatus = ResultStatus.OK,
    evidence: Sequence[Evidence] = (),
    relationships: Sequence[Relationship] = (),
    references: Sequence[Reference] = (),
    tags: Sequence[str] = (),
    reputation: Reputation | None = None,
    metadata: dict[str, object] | None = None,
) -> IntelligenceResult:
    if status in (ResultStatus.OK, ResultStatus.NOT_FOUND, ResultStatus.UNSUPPORTED):
        return IntelligenceResult(
            provider=provider,
            provider_display_name=provider.title(),
            entity_type=_ENTITY_TYPE,
            entity_value=_ENTITY_VALUE,
            status=status,
            reputation=reputation,
            evidence=list(evidence),
            relationships=list(relationships),
            references=list(references),
            tags=list(tags),
            metadata=metadata or {},
        )
    # Error-ish statuses must carry an error.
    return IntelligenceResult.failure(
        provider=provider,
        provider_display_name=provider.title(),
        entity_type=_ENTITY_TYPE,
        entity_value=_ENTITY_VALUE,
        message=f"{provider} failed",
        status=status,
    )


def aggregate_all(results: Sequence[IntelligenceResult]):
    return aggregate(results, entity_type=_ENTITY_TYPE, entity_value=_ENTITY_VALUE)


FAMILY = Evidence(type=EvidenceType.MALWARE_FAMILY, summary="Family: Emotet", value="Emotet")
TAG_EVIDENCE = Evidence(type=EvidenceType.TAG, summary="Tag: exe", value="exe")
RELATIONSHIP = Relationship(
    relationship=RelationshipType.INDICATES,
    target_type=RelationshipTargetType.MALWARE_FAMILY,
    target_value="Emotet",
)
REFERENCE = Reference(title="Sample", url="https://bazaar.example/sample/abc/")


# --- single / multiple success ---


def test_single_provider_success() -> None:
    result = make_result(
        "malwarebazaar",
        evidence=[FAMILY],
        relationships=[RELATIONSHIP],
        references=[REFERENCE],
        tags=["exe"],
        reputation=Reputation(level=ReputationLevel.MALICIOUS),
        metadata={"file_type": "exe"},
    )
    agg = aggregate_all([result])

    assert agg.entity_type is _ENTITY_TYPE
    assert [p.provider for p in agg.providers] == ["malwarebazaar"]
    assert agg.providers[0].reputation is not None
    assert agg.evidence[0].sources == ["malwarebazaar"]
    assert agg.relationships[0].sources == ["malwarebazaar"]
    assert agg.references[0].sources == ["malwarebazaar"]
    assert agg.tags == ["exe"]
    assert agg.metadata == {"malwarebazaar": {"file_type": "exe"}}
    assert agg.has_findings


def test_multiple_providers_distinct_findings_are_all_kept() -> None:
    a = make_result("provider_a", evidence=[FAMILY])
    other = Evidence(type=EvidenceType.MALWARE_FAMILY, summary="Family: TrickBot", value="TrickBot")
    b = make_result("provider_b", evidence=[other])

    agg = aggregate_all([a, b])

    assert {p.provider for p in agg.providers} == {"provider_a", "provider_b"}
    values = {e.evidence.value for e in agg.evidence}
    assert values == {"Emotet", "TrickBot"}


# --- de-duplication with attribution ---


def test_duplicate_evidence_is_merged_with_both_sources() -> None:
    a = make_result("provider_a", evidence=[FAMILY])
    b = make_result("provider_b", evidence=[FAMILY])

    agg = aggregate_all([a, b])

    assert len(agg.evidence) == 1
    assert agg.evidence[0].sources == ["provider_a", "provider_b"]


def test_duplicate_references_are_merged() -> None:
    a = make_result("provider_a", references=[REFERENCE])
    b = make_result("provider_b", references=[REFERENCE])

    agg = aggregate_all([a, b])

    assert len(agg.references) == 1
    assert agg.references[0].sources == ["provider_a", "provider_b"]


def test_duplicate_relationships_are_merged() -> None:
    a = make_result("provider_a", relationships=[RELATIONSHIP])
    b = make_result("provider_b", relationships=[RELATIONSHIP])

    agg = aggregate_all([a, b])

    assert len(agg.relationships) == 1
    assert agg.relationships[0].sources == ["provider_a", "provider_b"]


def test_duplicate_tags_are_deduped_case_insensitively() -> None:
    a = make_result("provider_a", tags=["Emotet", "exe"])
    b = make_result("provider_b", tags=["emotet", "dll"])

    agg = aggregate_all([a, b])

    assert agg.tags == ["Emotet", "exe", "dll"]


# --- failure handling ---


def test_partial_failure_keeps_successful_findings() -> None:
    ok = make_result("provider_a", evidence=[FAMILY])
    timed_out = make_result("provider_b", status=ResultStatus.TIMEOUT)

    agg = aggregate_all([ok, timed_out])

    statuses = {p.provider: p.status for p in agg.providers}
    assert statuses == {
        "provider_a": ResultStatus.OK,
        "provider_b": ResultStatus.TIMEOUT,
    }
    # The failed provider contributes no findings, but the successful one is kept.
    assert len(agg.evidence) == 1
    assert agg.evidence[0].sources == ["provider_a"]
    assert agg.providers[1].error is not None


def test_not_found_and_unauthorized_contribute_attribution_only() -> None:
    nf = make_result("provider_a", status=ResultStatus.NOT_FOUND)
    unauth = make_result("provider_b", status=ResultStatus.UNAUTHORIZED)

    agg = aggregate_all([nf, unauth])

    assert agg.provider_count == 2
    assert agg.evidence == []
    assert not agg.has_findings


def test_complete_failure_returns_attribution_without_findings() -> None:
    results = [
        make_result("provider_a", status=ResultStatus.ERROR),
        make_result("provider_b", status=ResultStatus.TIMEOUT),
    ]

    agg = aggregate_all(results)

    assert agg.provider_count == 2
    assert agg.succeeded == []
    assert not agg.has_findings
    assert all(p.error is not None for p in agg.providers)


def test_empty_provider_list() -> None:
    agg = aggregate_all([])

    assert agg.entity_type is _ENTITY_TYPE
    assert agg.entity_value == _ENTITY_VALUE
    assert agg.providers == []
    assert agg.evidence == []
    assert agg.relationships == []
    assert agg.references == []
    assert agg.tags == []
    assert agg.metadata == {}
    assert not agg.has_findings


def test_metadata_is_namespaced_per_provider() -> None:
    a = make_result("provider_a", metadata={"file_type": "exe"})
    b = make_result("provider_b", metadata={"file_type": "dll", "country": "US"})

    agg = aggregate_all([a, b])

    assert agg.metadata == {
        "provider_a": {"file_type": "exe"},
        "provider_b": {"file_type": "dll", "country": "US"},
    }


def test_provider_order_is_preserved() -> None:
    results = [make_result(f"p{i}") for i in range(3)]
    agg = aggregate_all(results)
    assert [p.provider for p in agg.providers] == ["p0", "p1", "p2"]
