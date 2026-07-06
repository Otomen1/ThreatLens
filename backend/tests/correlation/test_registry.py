"""Tests for CorrelationRegistry: registration, ordering, and the seed set."""

from __future__ import annotations

import pytest

from threatlens.correlation.exceptions import DuplicateCorrelationRuleError
from threatlens.correlation.models import (
    CorrelationCategory,
    CorrelationRelationshipType,
    CorrelationRule,
)
from threatlens.correlation.registry import CorrelationRegistry, build_default_registry
from threatlens.correlation.rules import SEED_RULES
from threatlens.reasoning.models import FindingCategory


def _rule(rule_id: str, *, priority: int = 100) -> CorrelationRule:
    return CorrelationRule(
        id=rule_id,
        name=rule_id,
        description="d",
        category=CorrelationCategory.VULNERABLE_EXPOSED_SERVICE,
        required_categories=frozenset({FindingCategory.EXPOSURE, FindingCategory.VULNERABILITY}),
        relationship=CorrelationRelationshipType.EXPOSES,
        title="t",
        priority=priority,
    )


class TestRegistration:
    def test_register_and_get(self) -> None:
        registry = CorrelationRegistry()
        rule = _rule("r1")
        registry.register(rule)
        assert registry.get("r1") is rule
        assert "r1" in registry
        assert len(registry) == 1

    def test_duplicate_id_raises(self) -> None:
        registry = CorrelationRegistry()
        registry.register(_rule("r1"))
        with pytest.raises(DuplicateCorrelationRuleError):
            registry.register(_rule("r1"))

    def test_get_missing_returns_none(self) -> None:
        assert CorrelationRegistry().get("nope") is None

    def test_rules_ordered_by_priority_then_id(self) -> None:
        registry = CorrelationRegistry()
        registry.register(_rule("z", priority=50))
        registry.register(_rule("a", priority=50))
        registry.register(_rule("early", priority=10))
        assert [r.id for r in registry.rules] == ["early", "a", "z"]


class TestDefaultRegistry:
    def test_seeds_all_rules(self) -> None:
        registry = build_default_registry()
        assert len(registry) == len(SEED_RULES)

    def test_rule_ids_are_unique(self) -> None:
        ids = [r.id for r in SEED_RULES]
        assert len(ids) == len(set(ids))

    def test_ordering_is_deterministic(self) -> None:
        assert [r.id for r in build_default_registry().rules] == [
            r.id for r in build_default_registry().rules
        ]

    def test_no_two_rules_share_the_same_matching_signature(self) -> None:
        """No semantic duplication: no two rules fire on identical conditions.

        Phase 7.0's 12 seed rules happened to have a 1:1 rule-to-category
        mapping; Phase 7.1's expansion instead groups rules representing the
        same *kind* of pattern under a shared category (see
        ``CorrelationCategory``'s docstring), so categories are no longer
        expected to be distinct per rule. The real non-duplication invariant
        is that no two rules match on the exact same (required categories,
        same_subject) combination — that would make one of them redundant.
        """
        signatures = [(frozenset(r.required_categories), r.same_subject) for r in SEED_RULES]
        assert len(signatures) == len(set(signatures))
