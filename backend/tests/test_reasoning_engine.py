"""Tests for the reason() entry point and its /api/v1/investigate integration.

As of Phase 3.1b, reason() generates findings via the rule engine and populates
posture/overall confidence; recommendations remain empty until 3.1c. The endpoint
exposes the summary additively without breaking the existing response.
"""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi.testclient import TestClient

from threatlens.api.app import app
from threatlens.entities.models import Entity
from threatlens.entities.types import EntityType, ValidationStatus
from threatlens.providers.aggregation import AggregatedResult, AttributedEvidence, ProviderSummary
from threatlens.providers.results import (
    Evidence,
    EvidenceType,
    Reputation,
    ReputationLevel,
    ResultStatus,
)
from threatlens.reasoning import ConfidenceBand, FindingCategory, Severity, reason
from threatlens.reasoning.engine import ENGINE_VERSION

NOW = datetime(2024, 6, 1, tzinfo=UTC)


def _entity(type_: EntityType = EntityType.IPV4, value: str = "1.2.3.4") -> Entity:
    return Entity(
        type=type_,
        value=value,
        normalized_value=value,
        confidence=100,
        validation=ValidationStatus.VALID,
        possible_matches=[],
    )


def _empty(entity_type: EntityType = EntityType.IPV4, value: str = "1.2.3.4") -> AggregatedResult:
    return AggregatedResult(entity_type=entity_type, entity_value=value)


# --------------------------------------------------------------------------- #
# reason() unit behaviour
# --------------------------------------------------------------------------- #


class TestReason:
    def test_empty_investigation_is_insufficient(self) -> None:
        summary = reason(_entity(), _empty(), _empty(), now=NOW)
        assert summary.overall_confidence.band is ConfidenceBand.INSUFFICIENT
        assert summary.findings == []
        assert summary.recommendations == []
        assert summary.posture is Severity.INFORMATIONAL
        assert summary.engine_version == ENGINE_VERSION
        assert summary.entity_type is EntityType.IPV4
        assert summary.entity_value == "1.2.3.4"
        assert summary.generated_at == NOW

    def test_supporting_evidence_yields_confidence(self) -> None:
        ti = AggregatedResult(
            entity_type=EntityType.IPV4,
            entity_value="1.2.3.4",
            providers=[
                ProviderSummary(
                    provider="abuseipdb",
                    status=ResultStatus.OK,
                    reputation=Reputation(level=ReputationLevel.MALICIOUS, score=90),
                )
            ],
            evidence=[
                AttributedEvidence(
                    evidence=Evidence(type=EvidenceType.DETECTION, summary="malware detected"),
                    sources=["otx"],
                )
            ],
        )
        summary = reason(_entity(), ti, _empty(), now=NOW)
        assert summary.overall_confidence.band is not ConfidenceBand.INSUFFICIENT
        assert summary.overall_confidence.score > 0
        # 3.1b: a malicious IP now yields a finding; recommendations stay empty.
        assert any(
            FindingCategory.MALICIOUS_INFRASTRUCTURE in f.categories for f in summary.findings
        )
        assert summary.recommendations == []

    def test_deterministic_for_fixed_now(self) -> None:
        ti = AggregatedResult(
            entity_type=EntityType.IPV4,
            entity_value="1.2.3.4",
            evidence=[
                AttributedEvidence(
                    evidence=Evidence(type=EvidenceType.BLOCKLIST, summary="listed"),
                    sources=["abuseipdb"],
                )
            ],
        )
        assert reason(_entity(), ti, _empty(), now=NOW) == reason(_entity(), ti, _empty(), now=NOW)


# --------------------------------------------------------------------------- #
# API integration (additive, backwards compatible)
# --------------------------------------------------------------------------- #


class TestInvestigateSummaryIntegration:
    def test_summary_present_and_shaped(self) -> None:
        client = TestClient(app)
        body = client.post("/api/v1/investigate", json={"query": "T1059"}).json()
        assert "investigation_summary" in body
        summary = body["investigation_summary"]
        for key in (
            "entity_type",
            "entity_value",
            "posture",
            "overall_confidence",
            "categories",
            "findings",
            "recommendations",
            "engine_version",
            "generated_at",
        ):
            assert key in summary
        # 3.1b: T1059 now produces an attack-technique finding; recommendations empty.
        assert len(summary["findings"]) >= 1
        assert summary["recommendations"] == []
        assert summary["engine_version"] == ENGINE_VERSION

    def test_existing_fields_unchanged(self) -> None:
        client = TestClient(app)
        body = client.post("/api/v1/investigate", json={"query": "1.1.1.1"}).json()
        # Backwards compatibility: the prior response keys still exist.
        assert {"investigation_id", "entity", "threat_intelligence", "knowledge"}.issubset(body)
        assert "overall_confidence" in body["investigation_summary"]
