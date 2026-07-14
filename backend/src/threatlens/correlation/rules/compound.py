"""Compound (three-signal) correlation rules.

Each rule here requires **three** finding categories rather than two — a
strictly more specific, more severe pattern than any one of its two-category
subset rules (e.g. :data:`MALICIOUS_EXPOSED_KNOWN_EXPLOITED` requires
everything :mod:`.infrastructure`'s malicious+exposed rule does, *plus* a
known-exploited disposition). Firing a compound rule is not a duplicate of its
subset rules firing too — both stand: the subset rule reports the pairwise
signal, the compound rule reports the escalated, three-way one. The engine's
generic evaluator needs no change to support these: ``required_categories``
already has no upper bound, only ``Field(min_length=2)``.
"""

from __future__ import annotations

from ...reasoning.models import FindingCategory as FC
from ..models import CorrelationCategory as Cat
from ..models import CorrelationRelationshipType as Rel
from ..models import CorrelationRule

RULES: tuple[CorrelationRule, ...] = (
    CorrelationRule(
        id="malicious_exposed_known_exploited",
        name="Malicious, exposed infrastructure running a known-exploited service",
        description=(
            "An entity that is flagged as malicious infrastructure, has an "
            "exposed internet-facing service, and that service is affected by a "
            "known-exploited vulnerability — the union of the malicious+exposed "
            "and exposed+known-exploited signals on one subject."
        ),
        category=Cat.MULTI_SIGNAL_MALICIOUS_EXPOSURE,
        required_categories=frozenset(
            {FC.MALICIOUS_INFRASTRUCTURE, FC.EXPOSURE, FC.KNOWN_EXPLOITED}
        ),
        relationship=Rel.EXPOSES,
        title="Malicious, exposed infrastructure running a known-exploited service",
        priority=1,
    ),
    CorrelationRule(
        id="vulnerable_exposed_known_exploited",
        name="Internet-facing known-exploited vulnerability",
        description=(
            "An exposed internet-facing service that carries a vulnerability "
            "which is itself flagged known-exploited — a strictly more specific "
            "and more urgent pattern than exposure+vulnerability or "
            "exposure+known-exploited alone."
        ),
        category=Cat.MULTI_SIGNAL_VULNERABLE_EXPOSURE,
        required_categories=frozenset({FC.EXPOSURE, FC.VULNERABILITY, FC.KNOWN_EXPLOITED}),
        relationship=Rel.EXPLOITS,
        title="Internet-facing known-exploited vulnerability",
        priority=2,
    ),
    CorrelationRule(
        id="corroborated_malicious_exposed_infrastructure",
        name="Corroborated malicious infrastructure with exposed services",
        description=(
            "Malicious infrastructure with an independent corroborating "
            "reputation signal that also has exposed internet-facing services — "
            "the union of the malicious+reputation and malicious+exposed signals "
            "on one subject."
        ),
        category=Cat.CORROBORATED_MALICIOUS_EXPOSURE,
        required_categories=frozenset(
            {FC.MALICIOUS_INFRASTRUCTURE, FC.REPUTATION, FC.EXPOSURE}
        ),
        relationship=Rel.ASSOCIATED_WITH,
        title="Corroborated malicious infrastructure with exposed services",
        priority=3,
    ),
    CorrelationRule(
        id="misconfigured_vulnerable_exposure",
        name="Misconfigured, vulnerable, internet-facing service",
        description=(
            "An exposed internet-facing service that is both misconfigured and "
            "affected by a known vulnerability — the union of exposure+"
            "misconfiguration and exposure+vulnerability on one subject."
        ),
        category=Cat.MULTI_SIGNAL_MISCONFIGURED_VULNERABLE,
        required_categories=frozenset({FC.EXPOSURE, FC.MISCONFIGURATION, FC.VULNERABILITY}),
        relationship=Rel.EXPOSES,
        title="Misconfigured, vulnerable, internet-facing service",
        priority=4,
    ),
    CorrelationRule(
        id="actor_malware_technique_convergence",
        name="Threat actor, malware, and ATT&CK technique jointly observed",
        description=(
            "The investigation surfaced a threat actor, a known malware family, "
            "and an ATT&CK technique together — a strictly more specific "
            "attribution pattern than any single pairwise association among "
            "these three (actor+malware, actor+technique, or malware+technique)."
        ),
        category=Cat.ACTOR_MALWARE_TECHNIQUE_CONVERGENCE,
        required_categories=frozenset({FC.THREAT_ACTOR, FC.MALWARE, FC.ATTACK_PATTERN}),
        relationship=Rel.ATTRIBUTED_TO,
        title="Threat actor, malware, and ATT&CK technique jointly observed",
        same_subject=False,
        priority=5,
    ),
    CorrelationRule(
        id="campaign_actor_infrastructure_convergence",
        name="Campaign, threat actor, and malicious infrastructure jointly observed",
        description=(
            "The investigation surfaced a known campaign, a threat actor, and "
            "malicious infrastructure together — a strictly more specific "
            "attribution pattern than any single pairwise association among "
            "these three."
        ),
        category=Cat.CAMPAIGN_ACTOR_INFRASTRUCTURE_CONVERGENCE,
        required_categories=frozenset(
            {FC.CAMPAIGN, FC.THREAT_ACTOR, FC.MALICIOUS_INFRASTRUCTURE}
        ),
        relationship=Rel.ATTRIBUTED_TO,
        title="Campaign, threat actor, and malicious infrastructure jointly observed",
        same_subject=False,
        priority=6,
    ),
)
