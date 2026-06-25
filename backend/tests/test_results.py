"""Unit tests for the canonical Intelligence Result model (Phase 1.25).

Pure data-model tests: construction, validation, serialization, partial failure,
and forward compatibility. No providers, no network, no scoring.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

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
    ResultError,
    ResultStatus,
)


def _ok_result(**overrides: object) -> IntelligenceResult:
    base: dict[str, object] = {
        "provider": "virustotal",
        "provider_display_name": "VirusTotal",
        "entity_type": EntityType.IPV4,
        "entity_value": "185.100.10.15",
    }
    base.update(overrides)
    return IntelligenceResult(**base)  # type: ignore[arg-type]


# --- successful result creation ---


def test_successful_result_with_full_findings() -> None:
    result = _ok_result(
        reputation=Reputation(
            level=ReputationLevel.MALICIOUS,
            score=90,
            malicious_count=8,
            total_count=90,
            summary="8/90 engines flagged",
        ),
        evidence=[
            Evidence(
                type=EvidenceType.MALWARE_FAMILY,
                summary="Associated with Emotet",
                value="Emotet",
                confidence=80,
            ),
            Evidence(
                type=EvidenceType.LAST_SEEN,
                summary="Last seen 2024-01-02",
                observed_at=datetime(2024, 1, 2, tzinfo=UTC),
            ),
        ],
        relationships=[
            Relationship(
                relationship=RelationshipType.ASSOCIATED_WITH,
                target_type=RelationshipTargetType.MALWARE_FAMILY,
                target_value="Emotet",
                confidence=80,
            )
        ],
        references=[Reference(title="VT report", url="https://vt.example/ip/185.100.10.15")],
        tags=["botnet", "emotet"],
        fetched_at=datetime(2024, 1, 3, tzinfo=UTC),
    )

    assert result.status is ResultStatus.OK
    assert result.is_ok is True
    assert result.is_error is False
    assert result.has_findings is True
    assert result.error is None
    assert result.reputation is not None and result.reputation.level is ReputationLevel.MALICIOUS
    assert [e.value for e in result.evidence] == ["Emotet", None]
    assert result.relationships[0].target_value == "Emotet"
    assert result.tags == ["botnet", "emotet"]


def test_default_status_is_ok_and_findings_empty() -> None:
    result = _ok_result()
    assert result.status is ResultStatus.OK
    assert result.has_findings is False
    assert result.evidence == []
    assert result.relationships == []
    assert result.references == []
    assert result.metadata == {}


# --- empty result ---


def test_not_found_result() -> None:
    result = IntelligenceResult.not_found(
        provider="abuseipdb",
        entity_type=EntityType.IPV4,
        entity_value="8.8.8.8",
    )
    assert result.status is ResultStatus.NOT_FOUND
    assert result.is_ok is False
    assert result.is_error is False
    assert result.has_findings is False
    assert result.error is None


def test_unsupported_result() -> None:
    result = IntelligenceResult.unsupported(
        provider="malwarebazaar",
        entity_type=EntityType.IPV4,
        entity_value="8.8.8.8",
    )
    assert result.status is ResultStatus.UNSUPPORTED
    assert result.is_ok is False
    assert result.is_error is False
    assert result.has_findings is False
    assert result.error is None


# --- partial result ---


def test_partial_result_carries_findings_and_error() -> None:
    result = _ok_result(
        status=ResultStatus.PARTIAL,
        evidence=[Evidence(type=EvidenceType.TAG, summary="tagged: phishing", value="phishing")],
        error=ResultError(message="enrichment endpoint timed out", retryable=True),
    )
    assert result.status is ResultStatus.PARTIAL
    assert result.is_error is False  # partial is not a hard failure
    assert result.has_findings is True
    assert result.error is not None and result.error.retryable is True


# --- error result ---


def test_failure_result_factory() -> None:
    result = IntelligenceResult.failure(
        provider="virustotal",
        entity_type=EntityType.DOMAIN,
        entity_value="evil.example",
        message="503 from upstream",
        status=ResultStatus.ERROR,
        retryable=True,
        detail="service unavailable",
    )
    assert result.is_error is True
    assert result.has_findings is False
    assert result.error is not None
    assert result.error.message == "503 from upstream"
    assert result.error.retryable is True


@pytest.mark.parametrize(
    "status",
    [
        ResultStatus.ERROR,
        ResultStatus.TIMEOUT,
        ResultStatus.RATE_LIMITED,
        ResultStatus.UNAUTHORIZED,
    ],
)
def test_hard_error_status_requires_error(status: ResultStatus) -> None:
    with pytest.raises(ValidationError):
        _ok_result(status=status)  # no error attached


def test_ok_status_must_not_carry_error() -> None:
    with pytest.raises(ValidationError):
        _ok_result(error=ResultError(message="should not be here"))


# --- evidence serialization ---


def test_evidence_serialization_is_vendor_neutral_json() -> None:
    evidence = Evidence(
        type=EvidenceType.SANDBOX_OBSERVATION,
        summary="Contacted C2",
        value="10.0.0.5:443",
        confidence=75,
        observed_at=datetime(2024, 5, 1, 12, 0, tzinfo=UTC),
        data={"protocol": "https", "bytes_out": 2048},
    )
    dumped = evidence.model_dump(mode="json")
    assert dumped["type"] == "sandbox_observation"
    assert dumped["confidence"] == 75
    assert dumped["observed_at"].startswith("2024-05-01T12:00:00")
    assert dumped["data"] == {"protocol": "https", "bytes_out": 2048}


# --- relationship serialization ---


def test_relationship_serialization() -> None:
    rel = Relationship(
        relationship=RelationshipType.ATTRIBUTED_TO,
        target_type=RelationshipTargetType.THREAT_ACTOR,
        target_value="APT28",
        confidence=60,
    )
    dumped = rel.model_dump(mode="json")
    assert dumped == {
        "relationship": "attributed_to",
        "target_type": "threat_actor",
        "target_value": "APT28",
        "confidence": 60,
        "description": None,
    }


def test_relationship_chain_targets_are_all_expressible() -> None:
    # Entity -> Malware -> Actor -> Campaign -> CVE -> Technique -> Report
    chain = [
        RelationshipTargetType.MALWARE_FAMILY,
        RelationshipTargetType.THREAT_ACTOR,
        RelationshipTargetType.CAMPAIGN,
        RelationshipTargetType.VULNERABILITY,
        RelationshipTargetType.ATTACK_PATTERN,
        RelationshipTargetType.REPORT,
    ]
    rels = [
        Relationship(target_type=t, target_value=f"target-{t.value}") for t in chain
    ]
    assert [r.target_type for r in rels] == chain


# --- validation ---


def test_reputation_counts_must_be_consistent() -> None:
    Reputation(malicious_count=2, total_count=5)  # ok
    with pytest.raises(ValidationError):
        Reputation(malicious_count=10, total_count=5)


def test_score_and_confidence_bounds() -> None:
    with pytest.raises(ValidationError):
        Reputation(score=150)
    with pytest.raises(ValidationError):
        Evidence(type=EvidenceType.TAG, summary="x", confidence=-1)


def test_required_fields_are_validated() -> None:
    with pytest.raises(ValidationError):
        IntelligenceResult(  # type: ignore[call-arg]
            provider="", entity_type=EntityType.IPV4, entity_value="1.1.1.1"
        )
    with pytest.raises(ValidationError):
        Evidence(type=EvidenceType.TAG, summary="")


# --- forward compatibility ---


def test_round_trip_preserves_equality() -> None:
    result = _ok_result(
        reputation=Reputation(level=ReputationLevel.SUSPICIOUS, score=40),
        evidence=[Evidence(type=EvidenceType.CATEGORY, summary="malware", value="malware")],
        tags=["x"],
    )
    assert IntelligenceResult.model_validate(result.model_dump()) == result
    assert IntelligenceResult.model_validate_json(result.model_dump_json()) == result


def test_unknown_fields_are_ignored_for_forward_compat() -> None:
    payload = _ok_result().model_dump()
    payload["future_field"] = {"added": "in a later version"}
    payload["another_new_one"] = 123

    result = IntelligenceResult.model_validate(payload)

    assert result.provider == "virustotal"
    assert not hasattr(result, "future_field")
