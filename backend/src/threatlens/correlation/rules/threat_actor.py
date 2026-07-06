"""Threat-actor correlation rules: THREAT_ACTOR combined with every domain
category not already covered by the Phase 7.0 seed set.

The seed set covers actor+technique and actor+malware, both cross-subject
only. This module adds the same-subject variant of each, plus actor paired
with malicious infrastructure (both bindings — attribution across different
subjects vs. direct same-subject attribution), campaign, vulnerability,
exposure, reputation, and a contested-attribution disposition rule.
"""

from __future__ import annotations

from ...reasoning.models import FindingCategory as FC
from ..models import CorrelationCategory as Cat
from ..models import CorrelationRelationshipType as Rel
from ..models import CorrelationRule

RULES: tuple[CorrelationRule, ...] = (
    CorrelationRule(
        id="actor_technique_colocated",
        name="Threat actor and an ATT&CK technique observed on the same entity",
        description=(
            "A threat actor and an ATT&CK technique observed on the *same* "
            "subject — a tighter binding than the seed set's cross-subject "
            "actor+technique mapping."
        ),
        category=Cat.ACTOR_TECHNIQUE_COLOCATED,
        required_categories=frozenset({FC.THREAT_ACTOR, FC.ATTACK_PATTERN}),
        relationship=Rel.MAPPED_TO,
        title="Threat actor and an ATT&CK technique observed on the same entity",
        priority=131,
    ),
    CorrelationRule(
        id="actor_malware_colocated",
        name="Threat actor and known malware observed on the same entity",
        description=(
            "A threat actor and a known malware family observed on the *same* "
            "subject — a tighter binding than the seed set's cross-subject "
            "actor+malware association."
        ),
        category=Cat.ACTOR_MALWARE_COLOCATED,
        required_categories=frozenset({FC.THREAT_ACTOR, FC.MALWARE}),
        relationship=Rel.ATTRIBUTED_TO,
        title="Threat actor and known malware observed on the same entity",
        priority=132,
    ),
    CorrelationRule(
        id="actor_malicious_infrastructure",
        name="Threat actor associated with malicious infrastructure",
        description=(
            "The investigation surfaced both a threat actor and malicious "
            "infrastructure — possibly on different subjects (Threat "
            "Intelligence/Actor + Threat Intelligence)."
        ),
        category=Cat.ACTOR_INFRASTRUCTURE_LINK,
        required_categories=frozenset({FC.THREAT_ACTOR, FC.MALICIOUS_INFRASTRUCTURE}),
        relationship=Rel.ASSOCIATED_WITH,
        title="Threat actor associated with malicious infrastructure",
        same_subject=False,
        priority=133,
    ),
    CorrelationRule(
        id="actor_malicious_infrastructure_colocated",
        name="Threat actor directly attributed to malicious infrastructure",
        description=(
            "A threat actor and malicious infrastructure observed on the "
            "*same* subject — direct attribution, a tighter binding than "
            "co-occurrence elsewhere in the investigation."
        ),
        category=Cat.ACTOR_INFRASTRUCTURE_LINK,
        required_categories=frozenset({FC.THREAT_ACTOR, FC.MALICIOUS_INFRASTRUCTURE}),
        relationship=Rel.ATTRIBUTED_TO,
        title="Threat actor directly attributed to malicious infrastructure",
        priority=134,
    ),
    CorrelationRule(
        id="actor_campaign",
        name="Threat actor associated with a known campaign",
        description=(
            "The investigation surfaced both a threat actor and a known "
            "campaign (Threat Intelligence/Actor + Knowledge/Campaign)."
        ),
        category=Cat.ACTOR_CAMPAIGN_LINK,
        required_categories=frozenset({FC.THREAT_ACTOR, FC.CAMPAIGN}),
        relationship=Rel.ATTRIBUTED_TO,
        title="Threat actor associated with a known campaign",
        same_subject=False,
        priority=135,
    ),
    CorrelationRule(
        id="actor_vulnerability",
        name="Threat actor's infrastructure carrying a known vulnerability",
        description=(
            "A threat-actor finding on an entity that also carries a known "
            "vulnerability (Threat Intelligence/Actor + Knowledge/"
            "Vulnerability)."
        ),
        category=Cat.ACTOR_ASSET_ASSOCIATION,
        required_categories=frozenset({FC.THREAT_ACTOR, FC.VULNERABILITY}),
        relationship=Rel.ASSOCIATED_WITH,
        title="Threat actor's infrastructure carrying a known vulnerability",
        priority=136,
    ),
    CorrelationRule(
        id="actor_exposure",
        name="Threat actor's infrastructure with exposed services",
        description=(
            "A threat-actor finding on an entity that also has an exposed "
            "internet-facing service (Threat Intelligence/Actor + Exposure)."
        ),
        category=Cat.ACTOR_ASSET_ASSOCIATION,
        required_categories=frozenset({FC.THREAT_ACTOR, FC.EXPOSURE}),
        relationship=Rel.ASSOCIATED_WITH,
        title="Threat actor's infrastructure with exposed services",
        priority=137,
    ),
    CorrelationRule(
        id="actor_reputation",
        name="Threat actor corroborated by an independent reputation signal",
        description=(
            "A threat-actor finding on an entity that also carries an "
            "independent reputation signal (Threat Intelligence/Actor + "
            "reputation)."
        ),
        category=Cat.CORROBORATED_REPUTATION_SIGNAL,
        required_categories=frozenset({FC.THREAT_ACTOR, FC.REPUTATION}),
        relationship=Rel.ASSOCIATED_WITH,
        title="Threat actor corroborated by an independent reputation signal",
        priority=138,
    ),
    CorrelationRule(
        id="actor_attribution_contested",
        name="Threat-actor attribution contested across sources",
        description=(
            "A threat-actor finding on this entity whose disposition is also "
            "flagged contested — sources disagree on this specific "
            "attribution (Threat Intelligence/Actor + contested)."
        ),
        category=Cat.FINDING_CONTESTED,
        required_categories=frozenset({FC.THREAT_ACTOR, FC.CONTESTED}),
        relationship=Rel.CO_OCCURS_WITH,
        title="Threat-actor attribution contested across sources",
        priority=139,
    ),
)
