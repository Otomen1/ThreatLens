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
        assert len(registry) == len(SEED_RULES) == 12

    def test_rule_ids_are_unique(self) -> None:
        ids = [r.id for r in SEED_RULES]
        assert len(ids) == len(set(ids))

    def test_ordering_is_deterministic(self) -> None:
        assert [r.id for r in build_default_registry().rules] == [
            r.id for r in build_default_registry().rules
        ]

    def test_categories_are_distinct_per_rule(self) -> None:
        # Each seed rule emits a distinct correlation category (1:1 mapping).
        categories = [r.category for r in SEED_RULES]
        assert len(categories) == len(set(categories))
