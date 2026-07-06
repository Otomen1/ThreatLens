"""Each seed rule fires on its required categories and produces its observation."""

from __future__ import annotations

import pytest

from threatlens.correlation.engine import correlate, evaluate_rule
from threatlens.correlation.models import CorrelationRule
from threatlens.correlation.registry import build_default_registry
from threatlens.correlation.rules import SEED_RULES
from threatlens.reasoning.models import FindingCategory, InvestigationSummary

from .factories import finding, summary


def _summary_that_triggers(rule: CorrelationRule) -> InvestigationSummary:
    """Build a summary containing exactly the findings a rule requires.

    Same-subject rules put every required category on one subject; cross-subject
    rules spread them across distinct subjects, proving co-occurrence (not
    shared subject) is what those rules key on.
    """
    categories = sorted(rule.required_categories, key=lambda c: c.value)
    if rule.same_subject:
        findings = [
            finding(f"fnd_{i}", {cat}, subject_value="8.8.8.8") for i, cat in enumerate(categories)
        ]
    else:
        findings = [
            finding(f"fnd_{i}", {cat}, subject_value=f"10.0.0.{i}")
            for i, cat in enumerate(categories)
        ]
    return summary(findings)


@pytest.mark.parametrize("rule", SEED_RULES, ids=lambda r: r.id)
def test_rule_fires_on_its_required_categories(rule: CorrelationRule) -> None:
    observations = evaluate_rule(rule, _summary_that_triggers(rule))
    assert len(observations) == 1
    observation = observations[0]
    assert observation.rule_id == rule.id
    assert observation.category is rule.category
    assert observation.title == rule.title
    # Every required category is represented in the referenced evidence.
    matched = {e.matched_category for e in observation.evidence}
    assert rule.required_categories <= matched
    # Exactly the contributing findings are referenced (no invented ids).
    assert set(observation.source_finding_ids) == {
        f.id for f in _summary_that_triggers(rule).findings
    }


@pytest.mark.parametrize("rule", SEED_RULES, ids=lambda r: r.id)
def test_rule_does_not_fire_without_all_required_categories(rule: CorrelationRule) -> None:
    # Only the first required category present → the rule must not fire.
    first = sorted(rule.required_categories, key=lambda c: c.value)[0]
    assert evaluate_rule(rule, summary([finding("fnd_1", {first})])) == []


def test_full_registry_on_a_single_rule_input_produces_only_that_observation() -> None:
    # A summary with exactly one rule's categories yields exactly one observation.
    findings = [
        finding("fnd_1", {FindingCategory.EXPOSURE}),
        finding("fnd_2", {FindingCategory.VULNERABILITY}),
    ]
    result = correlate(summary(findings), registry=build_default_registry())
    assert result.statistics.total_observations == 1
    assert result.observations[0].rule_id == "vulnerable_exposed_service"
