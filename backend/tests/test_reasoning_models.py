"""Tests for the canonical reasoning models (Phase 3.1a).

Covers construction, immutability (frozen), field constraints, and the closed
enumerations. No engine logic is exercised here.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from threatlens.entities.types import EntityType
from threatlens.providers.aggregation import AttributedEvidence
from threatlens.providers.results import Evidence, EvidenceType
from threatlens.reasoning import (
    Confidence,
    ConfidenceBand,
    ConfidenceFactor,
    EvidenceDimension,
    EvidencePolarity,
    Finding,
    FindingCategory,
    InvestigationSummary,
    Recommendation,
    RecommendationAction,
    RecommendationCategory,
    Severity,
    WeightedEvidence,
)


def _attributed(
    value: str = "x", etype: EvidenceType = EvidenceType.DETECTION
) -> AttributedEvidence:
    return AttributedEvidence(
        evidence=Evidence(type=etype, summary=f"summary {value}", value=value),
        sources=["prov"],
    )


def _weighted(weight: float = 0.5) -> WeightedEvidence:
    return WeightedEvidence(
        evidence=_attributed(),
        weight=weight,
        polarity=EvidencePolarity.SUPPORTING,
        dimension=EvidenceDimension.REPUTATION,
    )


def _confidence(score: int = 50) -> Confidence:
    return Confidence(score=score, band=ConfidenceBand.MODERATE)


# --------------------------------------------------------------------------- #
# Enumerations
# --------------------------------------------------------------------------- #


class TestEnums:
    def test_severity_is_ordinal(self) -> None:
        assert Severity.CRITICAL > Severity.HIGH > Severity.MEDIUM > Severity.LOW
        assert max(Severity.LOW, Severity.CRITICAL) is Severity.CRITICAL

    def test_evidence_dimension_closed_set(self) -> None:
        assert {d.value for d in EvidenceDimension} == {
            "reputation",
            "exploitation",
            "exposure",
            "attribution",
            "weakness",
            "capability",
            "infrastructure",
        }

    def test_recommendation_categories_closed_set(self) -> None:
        assert {c.value for c in RecommendationCategory} == {
            "containment",
            "investigation",
            "remediation",
            "forensics",
        }


# --------------------------------------------------------------------------- #
# WeightedEvidence
# --------------------------------------------------------------------------- #


class TestWeightedEvidence:
    def test_construction_preserves_attribution(self) -> None:
        we = _weighted()
        assert we.evidence.sources == ["prov"]
        assert we.dimension is EvidenceDimension.REPUTATION

    def test_frozen(self) -> None:
        we = _weighted()
        with pytest.raises((ValidationError, TypeError, AttributeError)):
            we.weight = 0.9  # type: ignore[misc]

    def test_weight_upper_bound(self) -> None:
        with pytest.raises(ValidationError):
            _weighted(weight=1.5)

    def test_weight_lower_bound(self) -> None:
        with pytest.raises(ValidationError):
            _weighted(weight=-0.1)


# --------------------------------------------------------------------------- #
# Confidence
# --------------------------------------------------------------------------- #


class TestConfidence:
    def test_construction(self) -> None:
        c = Confidence(
            score=72,
            band=ConfidenceBand.HIGH,
            contested=False,
            factors=[ConfidenceFactor(name="authority", contribution=30, detail="d")],
        )
        assert c.score == 72
        assert c.factors[0].name == "authority"

    def test_score_upper_bound(self) -> None:
        with pytest.raises(ValidationError):
            Confidence(score=101, band=ConfidenceBand.HIGH)

    def test_score_lower_bound(self) -> None:
        with pytest.raises(ValidationError):
            Confidence(score=-1, band=ConfidenceBand.LOW)


# --------------------------------------------------------------------------- #
# Recommendation / Finding (model only)
# --------------------------------------------------------------------------- #


class TestRecommendation:
    def test_construction(self) -> None:
        rec = Recommendation(
            action=RecommendationAction.BLOCK,
            category=RecommendationCategory.CONTAINMENT,
            priority=0,
            target_type=EntityType.IPV4,
            target_value="1.2.3.4",
            rationale="because",
            rule_id="rule.block",
        )
        assert rec.action is RecommendationAction.BLOCK
        assert rec.category is RecommendationCategory.CONTAINMENT


class TestFinding:
    def test_construction(self) -> None:
        finding = Finding(
            id="abc123",
            title="Test finding",
            categories=frozenset({FindingCategory.VULNERABILITY, FindingCategory.KNOWN_EXPLOITED}),
            subject_type=EntityType.CVE,
            subject_value="CVE-2021-44228",
            severity=Severity.CRITICAL,
            confidence=_confidence(90),
        )
        assert FindingCategory.KNOWN_EXPLOITED in finding.categories
        assert finding.severity is Severity.CRITICAL
        assert finding.recommendations == []  # model-only; empty by default
        assert finding.priority == 0

    def test_frozen(self) -> None:
        finding = Finding(
            id="abc123",
            title="t",
            categories=frozenset({FindingCategory.REPUTATION}),
            subject_type=EntityType.IPV4,
            subject_value="1.2.3.4",
            severity=Severity.LOW,
            confidence=_confidence(),
        )
        with pytest.raises((ValidationError, TypeError, AttributeError)):
            finding.severity = Severity.HIGH  # type: ignore[misc]


# --------------------------------------------------------------------------- #
# InvestigationSummary
# --------------------------------------------------------------------------- #


class TestInvestigationSummary:
    def test_defaults(self) -> None:
        summary = InvestigationSummary(
            entity_type=EntityType.IPV4,
            entity_value="1.2.3.4",
            overall_confidence=_confidence(),
            engine_version="3.1a",
            generated_at=datetime(2024, 1, 1, tzinfo=UTC),
        )
        assert summary.posture is Severity.INFORMATIONAL
        assert summary.findings == []
        assert summary.recommendations == []
        assert summary.categories == frozenset()
