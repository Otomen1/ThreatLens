"""Deterministic detection quality and freshness coverage."""

from threatlens.detection import generate

from .corpus import CORPUS


def test_generated_rules_have_explainable_quality() -> None:
    scenario = next(item for item in CORPUS if not item.expect_empty)
    first = generate(scenario.summary)
    second = generate(scenario.summary)
    assert first == second
    assert first.artifacts
    assert all(0 <= artifact.quality.score <= 100 for artifact in first.artifacts)
    assert all(artifact.quality.deductions for artifact in first.artifacts)


def test_missing_observation_time_is_honestly_unknown() -> None:
    scenario = next(item for item in CORPUS if not item.expect_empty)
    package = generate(scenario.summary)
    assert {artifact.freshness.status.value for artifact in package.artifacts} == {"unknown"}
