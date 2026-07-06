"""Model serialization and vocabulary tests for the Correlation Engine."""

from __future__ import annotations

from threatlens.correlation.models import (
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
from threatlens.entities.types import EntityType
from threatlens.reasoning.models import FindingCategory

from .factories import NOW


def _observation() -> CorrelationObservation:
    return CorrelationObservation(
        id="cor_abc",
        rule_id="rule_x",
        category=CorrelationCategory.MALICIOUS_EXPOSED_INFRASTRUCTURE,
        title="t",
        summary="s",
        subject_type=EntityType.IPV4,
        subject_value="8.8.8.8",
        evidence=(
            CorrelationEvidence(
                finding_id="fnd_1",
                matched_category=FindingCategory.EXPOSURE,
                subject_type=EntityType.IPV4,
                subject_value="8.8.8.8",
                summary="finding",
            ),
        ),
        relationships=(
            CorrelationRelationship(
                type=CorrelationRelationshipType.EXPOSES,
                source_finding_id="fnd_1",
                target_finding_id="fnd_2",
            ),
        ),
        source_finding_ids=("fnd_1", "fnd_2"),
    )


class TestCorrelationRule:
    def test_requires_at_least_two_categories(self) -> None:
        import pytest
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            CorrelationRule(
                id="r",
                name="r",
                description="d",
                category=CorrelationCategory.VULNERABLE_EXPOSED_SERVICE,
                required_categories=frozenset({FindingCategory.EXPOSURE}),  # only one
                relationship=CorrelationRelationshipType.EXPOSES,
                title="t",
            )

    def test_default_same_subject_and_priority(self) -> None:
        rule = CorrelationRule(
            id="r",
            name="r",
            description="d",
            category=CorrelationCategory.VULNERABLE_EXPOSED_SERVICE,
            required_categories=frozenset(
                {FindingCategory.EXPOSURE, FindingCategory.VULNERABILITY}
            ),
            relationship=CorrelationRelationshipType.EXPOSES,
            title="t",
        )
        assert rule.same_subject is True
        assert rule.priority == 100


class TestObservationSerialization:
    def test_round_trip(self) -> None:
        obs = _observation()
        assert CorrelationObservation.model_validate_json(obs.model_dump_json()) == obs


class TestSummarySerialization:
    def test_round_trip(self) -> None:
        obs = _observation()
        summary = CorrelationSummary(
            id="cors_1",
            entity_type=EntityType.IPV4,
            entity_value="8.8.8.8",
            observations=(obs,),
            matches=(
                CorrelationMatch(
                    rule_id="rule_x", category=obs.category, observation_ids=("cor_abc",)
                ),
            ),
            statistics=CorrelationStatistics(
                rules_evaluated=12, rules_matched=1, total_observations=1, source_finding_count=2
            ),
            metadata=CorrelationMetadata(
                entity_type=EntityType.IPV4,
                entity_value="8.8.8.8",
                generated_at=NOW,
                framework_version="0.1.0",
                source_engine_version="1.0",
            ),
            source_finding_ids=("fnd_1", "fnd_2"),
        )
        assert CorrelationSummary.model_validate_json(summary.model_dump_json()) == summary
        assert summary.has_observations is True

    def test_empty_summary_has_no_observations(self) -> None:
        summary = CorrelationSummary(
            id="cors_0",
            entity_type=EntityType.IPV4,
            entity_value="8.8.8.8",
            statistics=CorrelationStatistics(),
            metadata=CorrelationMetadata(
                entity_type=EntityType.IPV4,
                entity_value="8.8.8.8",
                generated_at=NOW,
                framework_version="0.1.0",
                source_engine_version="1.0",
            ),
        )
        assert summary.has_observations is False
        assert summary.observations == ()


class TestVocabularies:
    def test_category_values_are_stable(self) -> None:
        assert CorrelationCategory.MALICIOUS_EXPOSED_INFRASTRUCTURE.value == (
            "malicious_exposed_infrastructure"
        )
        assert (
            CorrelationCategory.MALWARE_TECHNIQUE_ASSOCIATION.value
            == "malware_technique_association"
        )

    def test_relationship_values_are_stable(self) -> None:
        assert CorrelationRelationshipType.EXPOSES.value == "exposes"
        assert CorrelationRelationshipType.MAPPED_TO.value == "mapped_to"
