"""The correlation rule library (Phase 7.0 seed set + Phase 7.1 expansion).

One module per domain, each exporting a ``RULES`` tuple of declarative
:class:`~threatlens.correlation.models.CorrelationRule` data — no per-rule
code, so every rule stays trivially explainable, testable, and
drift-detectable via the golden regression. This package replaces the single
Phase 7.0 ``rules.py`` file; :func:`default_rules` and :data:`SEED_RULES`
keep their exact names and shape so ``registry.py`` and the package
``__init__.py`` need no changes.

Modules:

* ``seed`` — the original 12 Phase 7.0 rules, unchanged.
* ``compound`` — three-signal escalations (strictly more specific than any
  one of their two-category subset rules).
* ``infrastructure`` — MALICIOUS_INFRASTRUCTURE / EXPOSURE / REPUTATION /
  MISCONFIGURATION combinations, plus their disposition variants.
* ``vulnerability`` — VULNERABILITY / WEAKNESS / KNOWN_EXPLOITED
  combinations.
* ``malware`` — MALWARE combined with every other domain category.
* ``threat_actor`` — THREAT_ACTOR combined with every other domain category.
* ``campaign`` — CAMPAIGN combined with every other domain category.
* ``mitre`` — ATTACK_PATTERN combined with every category not already owned
  by ``malware``/``threat_actor``/``campaign`` (see that module's docstring
  for why this replaces the originally-sketched per-MITRE-tactic modules).

See ``docs/architecture/PHASE-7.1-CORRELATION-RULE-LIBRARY.md`` for the full
rule taxonomy, philosophy, and coverage rationale.
"""

from __future__ import annotations

from ..models import CorrelationRule
from . import campaign, compound, infrastructure, malware, mitre, seed, threat_actor, vulnerability

SEED_RULES: tuple[CorrelationRule, ...] = (
    seed.RULES
    + compound.RULES
    + infrastructure.RULES
    + vulnerability.RULES
    + malware.RULES
    + threat_actor.RULES
    + campaign.RULES
    + mitre.RULES
)
"""Every registered correlation rule (Phase 7.0 seed set + Phase 7.1 expansion)."""


def default_rules() -> tuple[CorrelationRule, ...]:
    """Return the default rule set (a stable, ordered tuple)."""
    return SEED_RULES
