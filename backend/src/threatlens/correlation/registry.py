"""The correlation-rule registry.

A small, explicit container — the extension seam for adding correlation
rules — mirroring ``detection/registry.py`` and the provider/exposure
registries. Rules are held keyed by unique id and exposed in a deterministic
priority-then-id order, so execution ordering is always stable with no
randomness and no plugins. No global mutable state, so tests build isolated
registries.
"""

from __future__ import annotations

from .exceptions import DuplicateCorrelationRuleError
from .models import CorrelationCategory, CorrelationRule
from .rules import default_rules


class CorrelationRegistry:
    """Holds correlation rules keyed by unique id, ordered deterministically."""

    def __init__(self) -> None:
        self._rules: dict[str, CorrelationRule] = {}

    def register(self, rule: CorrelationRule) -> None:
        """Add a rule; raise :class:`DuplicateCorrelationRuleError` on id clash."""
        if rule.id in self._rules:
            raise DuplicateCorrelationRuleError(rule.id)
        self._rules[rule.id] = rule

    def get(self, rule_id: str) -> CorrelationRule | None:
        """Return the registered rule with ``rule_id``, or ``None``."""
        return self._rules.get(rule_id)

    def __contains__(self, rule_id: object) -> bool:
        return rule_id in self._rules

    def __len__(self) -> int:
        return len(self._rules)

    @property
    def rules(self) -> tuple[CorrelationRule, ...]:
        """All rules, ordered by ascending priority then id (deterministic)."""
        return tuple(sorted(self._rules.values(), key=lambda r: (r.priority, r.id)))

    @property
    def categories(self) -> tuple[CorrelationCategory, ...]:
        """The distinct observation categories the registered rules can emit."""
        return tuple(sorted({r.category for r in self._rules.values()}, key=lambda c: c.value))


def build_default_registry() -> CorrelationRegistry:
    """Build the default correlation registry, seeded with the Phase 7.0 rules.

    Unlike the zero-provider Exposure/Identity frameworks, the Correlation
    framework ships a small seed rule set so the engine is exercised
    end-to-end. Registering more rules here is the single wiring point for
    Phase 7.1's rule expansion — no engine change is needed.
    """
    registry = CorrelationRegistry()
    for rule in default_rules():
        registry.register(rule)
    return registry
