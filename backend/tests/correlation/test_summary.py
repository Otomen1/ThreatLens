"""Tests for summary.build_correlation_summary / compute_summary_id aggregation."""

from __future__ import annotations

from threatlens.correlation.models import (
    CorrelationCategory,
    CorrelationObservation,
    CorrelationSummary,
)
from threatlens.correlation.summary import build_correlation_summary, compute_summary_id
from threatlens.entities.types import EntityType

from .factories import NOW


def _obs(oid: str, rule_id: str, category: CorrelationCategory) -> CorrelationObservation:
    return CorrelationObservation(
        id=oid,
        rule_id=rule_id,
        category=category,
        title="t",
        subject_type=EntityType.IPV4,
        subject_value="8.8.8.8",
        source_finding_ids=("fnd_1",),
    )


def _build(observations: list[CorrelationObservation]) -> CorrelationSummary:
    return build_correlation_summary(
        observations,
        entity_type=EntityType.IPV4,
        entity_value="8.8.8.8",
        source_engine_version="1.0",
        source_finding_ids=["fnd_1", "fnd_2"],
        framework_version="0.1.0",
        generated_at=NOW,
        rules_evaluated=12,
    )


class TestEmpty:
    def test_empty_yields_well_formed_summary(self) -> None:
        result = _build([])
        assert result.observations == ()
        assert result.matches == ()
        assert result.statistics.total_observations == 0
        assert result.statistics.rules_matched == 0
        assert result.statistics.rules_evaluated == 12
        assert result.statistics.source_finding_count == 2
        assert result.metadata.framework_version == "0.1.0"
        assert result.metadata.generated_at == NOW


class TestAggregation:
    def test_dedupes_observations_by_id(self) -> None:
        obs = _obs("cor_1", "r1", CorrelationCategory.VULNERABLE_EXPOSED_SERVICE)
        result = _build([obs, obs])
        assert len(result.observations) == 1

    def test_orders_observations_by_category(self) -> None:
        a = _obs("cor_a", "r1", CorrelationCategory.VULNERABLE_EXPOSED_SERVICE)
        b = _obs("cor_b", "r2", CorrelationCategory.ACTOR_TECHNIQUE_MAPPING)
        result = _build([a, b])
        categories = [o.category.value for o in result.observations]
        assert categories == sorted(categories)

    def test_matches_group_by_rule(self) -> None:
        a = _obs("cor_a", "r1", CorrelationCategory.VULNERABLE_EXPOSED_SERVICE)
        b = _obs("cor_b", "r1", CorrelationCategory.VULNERABLE_EXPOSED_SERVICE)
        c = _obs("cor_c", "r2", CorrelationCategory.ACTOR_TECHNIQUE_MAPPING)
        result = _build([a, b, c])
        by_rule = {m.rule_id: m for m in result.matches}
        assert set(by_rule) == {"r1", "r2"}
        assert set(by_rule["r1"].observation_ids) == {"cor_a", "cor_b"}
        assert result.statistics.rules_matched == 2

    def test_statistics_categories_reflect_observations(self) -> None:
        a = _obs("cor_a", "r1", CorrelationCategory.VULNERABLE_EXPOSED_SERVICE)
        result = _build([a])
        assert result.statistics.categories == frozenset(
            {CorrelationCategory.VULNERABLE_EXPOSED_SERVICE}
        )


class TestSummaryId:
    def test_id_is_stable_and_prefixed(self) -> None:
        sid = compute_summary_id(
            entity_type=EntityType.IPV4,
            entity_value="8.8.8.8",
            source_engine_version="1.0",
            observation_ids=["cor_b", "cor_a"],
        )
        assert sid.startswith("cors_")
        # Order-independent (ids are sorted before hashing).
        other = compute_summary_id(
            entity_type=EntityType.IPV4,
            entity_value="8.8.8.8",
            source_engine_version="1.0",
            observation_ids=["cor_a", "cor_b"],
        )
        assert sid == other

    def test_id_differs_on_different_observations(self) -> None:
        base = compute_summary_id(
            entity_type=EntityType.IPV4,
            entity_value="8.8.8.8",
            source_engine_version="1.0",
            observation_ids=["cor_a"],
        )
        changed = compute_summary_id(
            entity_type=EntityType.IPV4,
            entity_value="8.8.8.8",
            source_engine_version="1.0",
            observation_ids=["cor_b"],
        )
        assert base != changed
