"""The finding-rule registry.

A small, explicit container holding :class:`FindingRule` instances keyed by their
unique ``id`` and exposed in a deterministic order (sorted by id). Mirrors the
detector/provider registries: no global mutable state, so tests build isolated
registries with custom rule sets.
"""

from __future__ import annotations

from .rules import DEFAULT_FINDING_RULES, FindingRule


class DuplicateRuleError(ValueError):
    """Raised when registering a rule whose id already exists."""

    def __init__(self, rule_id: str) -> None:
        super().__init__(f"a finding rule with id {rule_id!r} is already registered")
        self.rule_id = rule_id


class RuleRegistry:
    """Holds finding rules keyed by unique id, exposed in deterministic order."""

    def __init__(self) -> None:
        self._rules: dict[str, FindingRule] = {}

    def register(self, rule: FindingRule) -> None:
        """Add a rule; raise on id clash."""
        if rule.id in self._rules:
            raise DuplicateRuleError(rule.id)
        self._rules[rule.id] = rule

    def __contains__(self, rule_id: object) -> bool:
        return rule_id in self._rules

    def __len__(self) -> int:
        return len(self._rules)

    @property
    def rules(self) -> tuple[FindingRule, ...]:
        """All registered rules, ordered by id (deterministic evaluation order)."""
        return tuple(self._rules[rule_id] for rule_id in sorted(self._rules))


def build_default_rule_registry() -> RuleRegistry:
    """Build a registry populated with the five Phase 3.1b validation rules."""
    registry = RuleRegistry()
    for rule_cls in DEFAULT_FINDING_RULES:
        registry.register(rule_cls())
    return registry
