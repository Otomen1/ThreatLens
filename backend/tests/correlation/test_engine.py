"""Engine behavior: determinism, content-addressed identity, ordering, purity."""

from __future__ import annotations

from datetime import UTC, datetime

from threatlens.correlation.engine import CORRELATION_FRAMEWORK_VERSION, correlate
from threatlens.correlation.rules import SEED_RULES
from threatlens.entities.types import EntityType
from threatlens.reasoning.models import FindingCategory as FC
from threatlens.reasoning.models import InvestigationSummary

from .factories import finding, summary


def _malicious_exposed() -> InvestigationSummary:
    return summary(
        [finding("fnd_1", {FC.MALICIOUS_INFRASTRUCTURE}), finding("fnd_2", {FC.EXPOSURE})]
    )


class TestEmptyAndNoMatch:
    def test_empty_investigation_yields_empty_summary(self) -> None:
        result = correlate(summary([]))
        assert result.observations == ()
        assert result.statistics.total_observations == 0
        assert result.statistics.rules_matched == 0
        assert result.statistics.rules_evaluated == len(SEED_RULES)
        assert result.has_observations is False

    def test_single_finding_produces_no_observation(self) -> None:
        result = correlate(summary([finding("fnd_1", {FC.MALICIOUS_INFRASTRUCTURE})]))
        assert result.observations == ()

    def test_metadata_and_source_are_preserved(self) -> None:
        result = correlate(_malicious_exposed())
        assert result.entity_type is EntityType.IPV4
        assert result.entity_value == "8.8.8.8"
        assert result.metadata.framework_version == CORRELATION_FRAMEWORK_VERSION
        assert result.metadata.source_engine_version == "1.0"
        assert set(result.source_finding_ids) == {"fnd_1", "fnd_2"}


class TestDeterminismAndIdentity:
    def test_identical_input_yields_identical_output(self) -> None:
        assert correlate(_malicious_exposed()) == correlate(_malicious_exposed())

    def test_ids_are_content_addressed(self) -> None:
        result = correlate(_malicious_exposed())
        assert result.id.startswith("cors_")
        assert result.observations[0].id.startswith("cor_")

    def test_id_is_timestamp_independent(self) -> None:
        base = _malicious_exposed()
        later = base.model_copy(update={"generated_at": datetime(2030, 6, 6, tzinfo=UTC)})
        a, b = correlate(base), correlate(later)
        assert a.id == b.id
        assert [o.id for o in a.observations] == [o.id for o in b.observations]
        # generated_at itself is inherited, so it differs — only identity is stable.
        assert a.metadata.generated_at != b.metadata.generated_at

    def test_generated_at_is_inherited_not_wall_clock(self) -> None:
        result = correlate(_malicious_exposed())
        assert result.metadata.generated_at == datetime(2024, 1, 1, tzinfo=UTC)


class TestReadOnly:
    def test_input_summary_is_not_mutated(self) -> None:
        original = _malicious_exposed()
        snapshot = original.model_dump_json()
        correlate(original)
        assert original.model_dump_json() == snapshot


class TestOrderingAndAggregation:
    def test_observations_are_ordered_deterministically(self) -> None:
        result = correlate(
            summary(
                [
                    finding("fnd_1", {FC.MALICIOUS_INFRASTRUCTURE}),
                    finding("fnd_2", {FC.EXPOSURE}),
                    finding("fnd_3", {FC.VULNERABILITY}),
                    finding("fnd_4", {FC.KNOWN_EXPLOITED}),
                ]
            )
        )
        categories = [o.category.value for o in result.observations]
        assert categories == sorted(categories)  # ordered by category value

    def test_matches_reference_observations_by_id(self) -> None:
        result = correlate(_malicious_exposed())
        assert len(result.matches) == 1
        match = result.matches[0]
        assert match.rule_id == "malicious_exposed_infrastructure"
        assert set(match.observation_ids) == {o.id for o in result.observations}

    def test_statistics_are_accurate(self) -> None:
        result = correlate(_malicious_exposed())
        assert result.statistics.total_observations == 1
        assert result.statistics.rules_matched == 1
        assert result.statistics.source_finding_count == 2
        assert result.statistics.categories == frozenset({result.observations[0].category})


class TestSubjectHandling:
    def test_same_subject_rule_fans_out_per_subject(self) -> None:
        result = correlate(
            summary(
                [
                    finding("fnd_1", {FC.MALICIOUS_INFRASTRUCTURE}, subject_value="1.1.1.1"),
                    finding("fnd_2", {FC.EXPOSURE}, subject_value="1.1.1.1"),
                    finding("fnd_3", {FC.MALICIOUS_INFRASTRUCTURE}, subject_value="2.2.2.2"),
                    finding("fnd_4", {FC.EXPOSURE}, subject_value="2.2.2.2"),
                ]
            )
        )
        obs = [o for o in result.observations if o.rule_id == "malicious_exposed_infrastructure"]
        assert {o.subject_value for o in obs} == {"1.1.1.1", "2.2.2.2"}
        assert len(obs) == 2

    def test_same_subject_rule_does_not_cross_subjects(self) -> None:
        # Malicious on one IP, exposure on another → no same-subject correlation.
        result = correlate(
            summary(
                [
                    finding("fnd_1", {FC.MALICIOUS_INFRASTRUCTURE}, subject_value="1.1.1.1"),
                    finding("fnd_2", {FC.EXPOSURE}, subject_value="2.2.2.2"),
                ]
            )
        )
        assert all(o.rule_id != "malicious_exposed_infrastructure" for o in result.observations)

    def test_single_multicategory_finding_makes_no_self_relationship(self) -> None:
        result = correlate(summary([finding("fnd_1", {FC.MALICIOUS_INFRASTRUCTURE, FC.EXPOSURE})]))
        obs = [o for o in result.observations if o.rule_id == "malicious_exposed_infrastructure"]
        assert len(obs) == 1
        assert obs[0].relationships == ()  # one finding satisfied both → no self-link
        assert obs[0].source_finding_ids == ("fnd_1",)

    def test_duplicate_findings_are_referenced_without_duplicate_evidence_pairs(self) -> None:
        result = correlate(
            summary(
                [
                    finding("fnd_1", {FC.MALICIOUS_INFRASTRUCTURE}),
                    finding("fnd_2", {FC.MALICIOUS_INFRASTRUCTURE}),
                    finding("fnd_3", {FC.EXPOSURE}),
                ]
            )
        )
        obs = next(
            o for o in result.observations if o.rule_id == "malicious_exposed_infrastructure"
        )
        pairs = [(e.finding_id, e.matched_category) for e in obs.evidence]
        assert len(pairs) == len(set(pairs))  # no duplicate (finding, category) evidence
        assert set(obs.source_finding_ids) == {"fnd_1", "fnd_2", "fnd_3"}


class TestNeverInventsEvidence:
    def test_every_referenced_finding_exists_in_the_investigation(self) -> None:
        source = _malicious_exposed()
        valid_ids = {f.id for f in source.findings}
        result = correlate(source)
        for observation in result.observations:
            assert set(observation.source_finding_ids) <= valid_ids
            for evidence in observation.evidence:
                assert evidence.finding_id in valid_ids
            for relationship in observation.relationships:
                assert relationship.source_finding_id in valid_ids
                assert relationship.target_finding_id in valid_ids
