"""ATT&CK-technique correlation rules: ATTACK_PATTERN combined with every
domain/disposition category not already covered elsewhere.

Deliberate scope note (see the Phase 7.1 architecture doc's "Known
Limitations"): ``FindingCategory`` carries a single, tactic-agnostic
``ATTACK_PATTERN`` value — there is no per-MITRE-tactic category (no
distinct "persistence technique" vs. "execution technique" evidence). This
module is therefore the single home for every technique-co-occurrence rule,
rather than being split across per-tactic modules (persistence.py,
execution.py, discovery.py, collection.py, exfiltration.py,
command_and_control.py, lateral_movement.py, privilege_escalation.py,
impact.py) as first sketched — splitting would have produced rules that
differ only in their display text, not in what they actually match, which is
exactly the semantic duplication this rule library is meant to avoid. The
malware+technique, actor+technique, and campaign+technique pairs already live
in :mod:`.malware`, :mod:`.threat_actor`, and :mod:`.campaign` respectively
(each pairing is filed with its *other* anchor category); this module owns
every remaining ATTACK_PATTERN pairing.
"""

from __future__ import annotations

from ...reasoning.models import FindingCategory as FC
from ..models import CorrelationCategory as Cat
from ..models import CorrelationRelationshipType as Rel
from ..models import CorrelationRule

RULES: tuple[CorrelationRule, ...] = (
    CorrelationRule(
        id="attack_pattern_malicious_infrastructure",
        name="ATT&CK technique observed on malicious infrastructure",
        description=(
            "An ATT&CK technique observed on an entity that is also flagged as "
            "malicious infrastructure (Knowledge/ATT&CK + Threat Intelligence)."
        ),
        category=Cat.TECHNIQUE_INFRASTRUCTURE_LINK,
        required_categories=frozenset({FC.ATTACK_PATTERN, FC.MALICIOUS_INFRASTRUCTURE}),
        relationship=Rel.MAPPED_TO,
        title="ATT&CK technique observed on malicious infrastructure",
        priority=151,
    ),
    CorrelationRule(
        id="attack_pattern_exposure",
        name="ATT&CK technique observed on an exposed entity",
        description=(
            "An ATT&CK technique observed on an entity that also has an "
            "exposed internet-facing service (Knowledge/ATT&CK + Exposure)."
        ),
        category=Cat.TECHNIQUE_INFRASTRUCTURE_LINK,
        required_categories=frozenset({FC.ATTACK_PATTERN, FC.EXPOSURE}),
        relationship=Rel.MAPPED_TO,
        title="ATT&CK technique observed on an exposed entity",
        priority=152,
    ),
    CorrelationRule(
        id="attack_pattern_misconfiguration",
        name="ATT&CK technique linked to a misconfigured service",
        description=(
            "An ATT&CK technique observed on an entity that also has a "
            "misconfigured service (Knowledge/ATT&CK + misconfiguration)."
        ),
        category=Cat.TECHNIQUE_INFRASTRUCTURE_LINK,
        required_categories=frozenset({FC.ATTACK_PATTERN, FC.MISCONFIGURATION}),
        relationship=Rel.MAPPED_TO,
        title="ATT&CK technique linked to a misconfigured service",
        priority=153,
    ),
    CorrelationRule(
        id="attack_pattern_vulnerability",
        name="ATT&CK technique linked to a vulnerable entity",
        description=(
            "An ATT&CK technique observed on an entity that also carries a "
            "known vulnerability (Knowledge/ATT&CK + Knowledge/Vulnerability)."
        ),
        category=Cat.TECHNIQUE_VULNERABILITY_LINK,
        required_categories=frozenset({FC.ATTACK_PATTERN, FC.VULNERABILITY}),
        relationship=Rel.EXPLOITS,
        title="ATT&CK technique linked to a vulnerable entity",
        priority=154,
    ),
    CorrelationRule(
        id="attack_pattern_known_exploited",
        name="ATT&CK technique linked to a known-exploited vulnerability",
        description=(
            "An ATT&CK technique observed on an entity that also carries a "
            "known-exploited vulnerability (Knowledge/ATT&CK + "
            "known-exploited)."
        ),
        category=Cat.TECHNIQUE_VULNERABILITY_LINK,
        required_categories=frozenset({FC.ATTACK_PATTERN, FC.KNOWN_EXPLOITED}),
        relationship=Rel.EXPLOITS,
        title="ATT&CK technique linked to a known-exploited vulnerability",
        priority=155,
    ),
    CorrelationRule(
        id="attack_pattern_weakness",
        name="ATT&CK technique linked to an underlying weakness",
        description=(
            "An ATT&CK technique observed on an entity that also carries an "
            "underlying weakness class (Knowledge/ATT&CK + Knowledge/"
            "Weakness)."
        ),
        category=Cat.TECHNIQUE_VULNERABILITY_LINK,
        required_categories=frozenset({FC.ATTACK_PATTERN, FC.WEAKNESS}),
        relationship=Rel.ASSOCIATED_WITH,
        title="ATT&CK technique linked to an underlying weakness",
        priority=156,
    ),
    CorrelationRule(
        id="attack_pattern_reputation",
        name="ATT&CK technique corroborated by an independent reputation signal",
        description=(
            "An ATT&CK technique observed on an entity that also carries an "
            "independent reputation signal (Knowledge/ATT&CK + reputation)."
        ),
        category=Cat.CORROBORATED_REPUTATION_SIGNAL,
        required_categories=frozenset({FC.ATTACK_PATTERN, FC.REPUTATION}),
        relationship=Rel.ASSOCIATED_WITH,
        title="ATT&CK technique corroborated by an independent reputation signal",
        priority=157,
    ),
    CorrelationRule(
        id="attack_pattern_contested",
        name="ATT&CK technique mapping contested across sources",
        description=(
            "An ATT&CK technique mapping on this entity whose disposition is "
            "also flagged contested (Knowledge/ATT&CK + contested)."
        ),
        category=Cat.FINDING_CONTESTED,
        required_categories=frozenset({FC.ATTACK_PATTERN, FC.CONTESTED}),
        relationship=Rel.CO_OCCURS_WITH,
        title="ATT&CK technique mapping contested across sources",
        priority=158,
    ),
    CorrelationRule(
        id="attack_pattern_action_required",
        name="ATT&CK technique flagged for required action",
        description=(
            "An ATT&CK technique mapping on this entity whose disposition is "
            "also flagged action-required (Knowledge/ATT&CK + "
            "action-required)."
        ),
        category=Cat.FINDING_REQUIRES_ACTION,
        required_categories=frozenset({FC.ATTACK_PATTERN, FC.ACTION_REQUIRED}),
        relationship=Rel.CO_OCCURS_WITH,
        title="ATT&CK technique flagged for required action",
        priority=159,
    ),
)
