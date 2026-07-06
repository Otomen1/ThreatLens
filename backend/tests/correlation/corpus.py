"""A deterministic corpus of InvestigationSummary scenarios for the golden.

Each scenario exercises a specific rule (or edge case) so the golden snapshot
pins the engine's output for the whole rule library plus the tricky paths:
empty investigations, single findings, multi-subject same-rule fan-out,
duplicate findings, a single multi-category finding, and a rich investigation
firing several rules at once.

The 12 Phase 7.0 seed-rule scenarios below are hand-written (unchanged since
Phase 7.0). The Phase 7.1 rule library expansion (58 new rules) is covered by
:data:`_GENERATED_RULE_SCENARIOS`, generated once per registered rule from its
own ``required_categories``/``same_subject`` — mirroring
``test_rules.py``'s ``_summary_that_triggers`` — rather than hand-writing 58
near-identical dataclass literals.
"""

from __future__ import annotations

from dataclasses import dataclass

from threatlens.correlation.models import CorrelationRule
from threatlens.correlation.rules import SEED_RULES
from threatlens.entities.types import EntityType
from threatlens.reasoning.models import Finding, InvestigationSummary
from threatlens.reasoning.models import FindingCategory as FC

from .factories import finding, summary


@dataclass(frozen=True)
class Scenario:
    id: str
    summary: InvestigationSummary


def _ip(fid: str, cats: set[FC], value: str = "8.8.8.8") -> Finding:
    return finding(fid, cats, subject_type=EntityType.IPV4, subject_value=value)


def _scenario_for_rule(rule: CorrelationRule) -> Scenario:
    """Build the minimal summary that fires exactly ``rule``, as one scenario.

    Same-subject rules put every required category on one IPv4 subject;
    cross-subject rules spread them across distinct subjects, proving
    co-occurrence — not a shared subject — is what those rules key on.
    """
    categories = sorted(rule.required_categories, key=lambda c: c.value)
    if rule.same_subject:
        findings = [_ip(f"{rule.id}_{i}", {cat}) for i, cat in enumerate(categories)]
    else:
        findings = [
            _ip(f"{rule.id}_{i}", {cat}, value=f"10.{i}.0.1") for i, cat in enumerate(categories)
        ]
    return Scenario(rule.id, summary(findings))


_HAND_WRITTEN_SCENARIOS: tuple[Scenario, ...] = (
    Scenario("empty", summary([])),
    Scenario("single_finding_no_match", summary([_ip("fnd_1", {FC.MALICIOUS_INFRASTRUCTURE})])),
    Scenario(
        "malicious_exposed_infrastructure",
        summary([_ip("fnd_1", {FC.MALICIOUS_INFRASTRUCTURE}), _ip("fnd_2", {FC.EXPOSURE})]),
    ),
    Scenario(
        "vulnerable_exposed_service",
        summary([_ip("fnd_1", {FC.EXPOSURE}), _ip("fnd_2", {FC.VULNERABILITY})]),
    ),
    Scenario(
        "known_exploited_vulnerability",
        summary([_ip("fnd_1", {FC.VULNERABILITY}), _ip("fnd_2", {FC.KNOWN_EXPLOITED})]),
    ),
    Scenario(
        "known_exploited_exposure",
        summary([_ip("fnd_1", {FC.EXPOSURE}), _ip("fnd_2", {FC.KNOWN_EXPLOITED})]),
    ),
    Scenario(
        "reputation_confirmed_infrastructure",
        summary([_ip("fnd_1", {FC.MALICIOUS_INFRASTRUCTURE}), _ip("fnd_2", {FC.REPUTATION})]),
    ),
    Scenario(
        "misconfigured_exposed_service",
        summary([_ip("fnd_1", {FC.EXPOSURE}), _ip("fnd_2", {FC.MISCONFIGURATION})]),
    ),
    Scenario(
        "vulnerability_weakness_link",
        summary([_ip("fnd_1", {FC.VULNERABILITY}), _ip("fnd_2", {FC.WEAKNESS})]),
    ),
    Scenario(
        "malware_technique_association",
        summary(
            [
                finding(
                    "fnd_1",
                    {FC.MALWARE},
                    subject_type=EntityType.MALWARE_FAMILY,
                    subject_value="emotet",
                ),
                finding(
                    "fnd_2",
                    {FC.ATTACK_PATTERN},
                    subject_type=EntityType.MITRE_TECHNIQUE,
                    subject_value="T1059",
                ),
            ]
        ),
    ),
    Scenario(
        "actor_technique_mapping",
        summary(
            [
                finding(
                    "fnd_1",
                    {FC.THREAT_ACTOR},
                    subject_type=EntityType.THREAT_ACTOR,
                    subject_value="APT28",
                ),
                finding(
                    "fnd_2",
                    {FC.ATTACK_PATTERN},
                    subject_type=EntityType.MITRE_TECHNIQUE,
                    subject_value="T1059",
                ),
            ]
        ),
    ),
    Scenario(
        "actor_malware_association",
        summary(
            [
                finding(
                    "fnd_1",
                    {FC.THREAT_ACTOR},
                    subject_type=EntityType.THREAT_ACTOR,
                    subject_value="APT28",
                ),
                finding(
                    "fnd_2",
                    {FC.MALWARE},
                    subject_type=EntityType.MALWARE_FAMILY,
                    subject_value="emotet",
                ),
            ]
        ),
    ),
    Scenario(
        "campaign_infrastructure",
        summary(
            [
                finding(
                    "fnd_1", {FC.CAMPAIGN}, subject_type=EntityType.FREETEXT, subject_value="op-x"
                ),
                _ip("fnd_2", {FC.MALICIOUS_INFRASTRUCTURE}),
            ]
        ),
    ),
    Scenario(
        "malware_infrastructure_association",
        summary(
            [
                finding(
                    "fnd_1",
                    {FC.MALWARE},
                    subject_type=EntityType.MALWARE_FAMILY,
                    subject_value="emotet",
                ),
                _ip("fnd_2", {FC.MALICIOUS_INFRASTRUCTURE}),
            ]
        ),
    ),
    # Edge cases -------------------------------------------------------------- #
    Scenario(
        "multi_subject_same_rule",
        summary(
            [
                _ip("fnd_1", {FC.MALICIOUS_INFRASTRUCTURE}, value="1.1.1.1"),
                _ip("fnd_2", {FC.EXPOSURE}, value="1.1.1.1"),
                _ip("fnd_3", {FC.MALICIOUS_INFRASTRUCTURE}, value="2.2.2.2"),
                _ip("fnd_4", {FC.EXPOSURE}, value="2.2.2.2"),
            ]
        ),
    ),
    Scenario(
        "single_multicategory_finding",
        summary([_ip("fnd_1", {FC.MALICIOUS_INFRASTRUCTURE, FC.EXPOSURE})]),
    ),
    Scenario(
        "duplicate_findings",
        summary(
            [
                _ip("fnd_1", {FC.MALICIOUS_INFRASTRUCTURE}),
                _ip("fnd_2", {FC.MALICIOUS_INFRASTRUCTURE}),
                _ip("fnd_3", {FC.EXPOSURE}),
            ]
        ),
    ),
    Scenario(
        "rich_multi_rule",
        summary(
            [
                _ip("fnd_1", {FC.MALICIOUS_INFRASTRUCTURE}),
                _ip("fnd_2", {FC.EXPOSURE}),
                _ip("fnd_3", {FC.VULNERABILITY}),
                _ip("fnd_4", {FC.KNOWN_EXPLOITED}),
                _ip("fnd_5", {FC.REPUTATION}),
                finding(
                    "fnd_6",
                    {FC.MALWARE},
                    subject_type=EntityType.MALWARE_FAMILY,
                    subject_value="emotet",
                ),
                finding(
                    "fnd_7",
                    {FC.ATTACK_PATTERN},
                    subject_type=EntityType.MITRE_TECHNIQUE,
                    subject_value="T1059",
                ),
            ]
        ),
    ),
)

_HAND_WRITTEN_IDS = {s.id for s in _HAND_WRITTEN_SCENARIOS}

_GENERATED_RULE_SCENARIOS: tuple[Scenario, ...] = tuple(
    _scenario_for_rule(rule) for rule in SEED_RULES if rule.id not in _HAND_WRITTEN_IDS
)
"""One golden scenario per Phase 7.1 rule not already covered above."""

CORPUS: tuple[Scenario, ...] = _HAND_WRITTEN_SCENARIOS + _GENERATED_RULE_SCENARIOS
