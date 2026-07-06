"""The Phase 7.0 seed correlation rule set (unchanged since Phase 7.0).

A small, deterministic starter set of 12 rules combining *existing* finding
categories into higher-level observations. Each rule is declarative
:class:`CorrelationRule` data interpreted by the engine's single generic
evaluator — there is no per-rule code, so every rule is trivially explainable
and drift-testable.

Every rule combines findings that already exist in the ``InvestigationSummary``
and references them by id. No rule invents evidence, computes a score, or
emits confidence/severity/priority. Phase 7.1 (rule library expansion) adds
new rules in sibling modules (``infrastructure.py``, ``vulnerability.py``,
``malware.py``, ``threat_actor.py``, ``campaign.py``, ``mitre.py``,
``compound.py``) without touching this one.
"""

from __future__ import annotations

from ...reasoning.models import FindingCategory
from ..models import CorrelationCategory, CorrelationRelationshipType, CorrelationRule

# --------------------------------------------------------------------------- #
# Same-subject rules — the combined findings must share one subject entity.
# --------------------------------------------------------------------------- #

_SAME_SUBJECT_RULES: tuple[CorrelationRule, ...] = (
    CorrelationRule(
        id="malicious_exposed_infrastructure",
        name="Malicious infrastructure with exposed services",
        description=(
            "An entity flagged as malicious infrastructure that also has exposed "
            "internet-facing services (Threat Intelligence + Exposure)."
        ),
        category=CorrelationCategory.MALICIOUS_EXPOSED_INFRASTRUCTURE,
        required_categories=frozenset(
            {FindingCategory.MALICIOUS_INFRASTRUCTURE, FindingCategory.EXPOSURE}
        ),
        relationship=CorrelationRelationshipType.EXPOSES,
        title="Malicious infrastructure with exposed services",
        priority=10,
    ),
    CorrelationRule(
        id="vulnerable_exposed_service",
        name="Internet-facing vulnerable service",
        description=(
            "An entity with an exposed service that is also affected by a known "
            "vulnerability (Exposure + Knowledge/Vulnerability)."
        ),
        category=CorrelationCategory.VULNERABLE_EXPOSED_SERVICE,
        required_categories=frozenset({FindingCategory.EXPOSURE, FindingCategory.VULNERABILITY}),
        relationship=CorrelationRelationshipType.EXPOSES,
        title="Internet-facing vulnerable service",
        priority=20,
    ),
    CorrelationRule(
        id="known_exploited_vulnerability",
        name="Known-exploited vulnerability present",
        description=(
            "A vulnerability on this entity that is flagged as known-exploited "
            "(Knowledge/Vulnerability + known-exploited disposition)."
        ),
        category=CorrelationCategory.KNOWN_EXPLOITED_VULNERABILITY,
        required_categories=frozenset(
            {FindingCategory.VULNERABILITY, FindingCategory.KNOWN_EXPLOITED}
        ),
        relationship=CorrelationRelationshipType.EXPLOITS,
        title="Known-exploited vulnerability present",
        priority=15,
    ),
    CorrelationRule(
        id="known_exploited_exposure",
        name="Exposed service affected by a known-exploited vulnerability",
        description=(
            "An exposed internet-facing service on an entity that also carries a "
            "known-exploited disposition (Exposure + known-exploited)."
        ),
        category=CorrelationCategory.KNOWN_EXPLOITED_EXPOSURE,
        required_categories=frozenset({FindingCategory.EXPOSURE, FindingCategory.KNOWN_EXPLOITED}),
        relationship=CorrelationRelationshipType.EXPOSES,
        title="Exposed service affected by a known-exploited vulnerability",
        priority=15,
    ),
    CorrelationRule(
        id="reputation_confirmed_infrastructure",
        name="Malicious infrastructure with corroborating reputation",
        description=(
            "Malicious infrastructure corroborated by an independent reputation "
            "signal on the same entity (Threat Intelligence + reputation)."
        ),
        category=CorrelationCategory.REPUTATION_CONFIRMED_INFRASTRUCTURE,
        required_categories=frozenset(
            {FindingCategory.MALICIOUS_INFRASTRUCTURE, FindingCategory.REPUTATION}
        ),
        relationship=CorrelationRelationshipType.ASSOCIATED_WITH,
        title="Malicious infrastructure with corroborating reputation",
        priority=40,
    ),
    CorrelationRule(
        id="misconfigured_exposed_service",
        name="Misconfigured internet-facing service",
        description=(
            "An exposed service on this entity that is also misconfigured "
            "(Exposure + misconfiguration)."
        ),
        category=CorrelationCategory.MISCONFIGURED_EXPOSED_SERVICE,
        required_categories=frozenset({FindingCategory.EXPOSURE, FindingCategory.MISCONFIGURATION}),
        relationship=CorrelationRelationshipType.EXPOSES,
        title="Misconfigured internet-facing service",
        priority=30,
    ),
    CorrelationRule(
        id="vulnerability_weakness_link",
        name="Vulnerability linked to an underlying weakness",
        description=(
            "A vulnerability on this entity linked to its underlying weakness "
            "class (Knowledge/Vulnerability + Knowledge/Weakness)."
        ),
        category=CorrelationCategory.VULNERABILITY_WEAKNESS_LINK,
        required_categories=frozenset({FindingCategory.VULNERABILITY, FindingCategory.WEAKNESS}),
        relationship=CorrelationRelationshipType.ASSOCIATED_WITH,
        title="Vulnerability linked to an underlying weakness",
        priority=50,
    ),
)

# --------------------------------------------------------------------------- #
# Cross-subject rules — the findings need only co-occur in the investigation.
# --------------------------------------------------------------------------- #

_CROSS_SUBJECT_RULES: tuple[CorrelationRule, ...] = (
    CorrelationRule(
        id="malware_technique_association",
        name="Known malware associated with an observed ATT&CK technique",
        description=(
            "The investigation surfaced both a known malware family and an ATT&CK "
            "technique (Threat Intelligence/Malware + Knowledge/ATT&CK)."
        ),
        category=CorrelationCategory.MALWARE_TECHNIQUE_ASSOCIATION,
        required_categories=frozenset({FindingCategory.MALWARE, FindingCategory.ATTACK_PATTERN}),
        relationship=CorrelationRelationshipType.ASSOCIATED_WITH,
        title="Known malware associated with an observed ATT&CK technique",
        same_subject=False,
        priority=60,
    ),
    CorrelationRule(
        id="actor_technique_mapping",
        name="Threat actor mapped to an observed ATT&CK technique",
        description=(
            "The investigation surfaced both a threat actor and an ATT&CK "
            "technique (Threat Intelligence/Actor + Knowledge/ATT&CK)."
        ),
        category=CorrelationCategory.ACTOR_TECHNIQUE_MAPPING,
        required_categories=frozenset(
            {FindingCategory.THREAT_ACTOR, FindingCategory.ATTACK_PATTERN}
        ),
        relationship=CorrelationRelationshipType.MAPPED_TO,
        title="Threat actor mapped to an observed ATT&CK technique",
        same_subject=False,
        priority=60,
    ),
    CorrelationRule(
        id="actor_malware_association",
        name="Threat actor associated with known malware",
        description=(
            "The investigation surfaced both a threat actor and a known malware "
            "family (Threat Intelligence/Actor + Threat Intelligence/Malware)."
        ),
        category=CorrelationCategory.ACTOR_MALWARE_ASSOCIATION,
        required_categories=frozenset({FindingCategory.THREAT_ACTOR, FindingCategory.MALWARE}),
        relationship=CorrelationRelationshipType.ATTRIBUTED_TO,
        title="Threat actor associated with known malware",
        same_subject=False,
        priority=65,
    ),
    CorrelationRule(
        id="campaign_infrastructure",
        name="Malicious infrastructure linked to a known campaign",
        description=(
            "The investigation surfaced both malicious infrastructure and a known "
            "campaign (Threat Intelligence + Knowledge/Campaign)."
        ),
        category=CorrelationCategory.CAMPAIGN_INFRASTRUCTURE,
        required_categories=frozenset(
            {FindingCategory.CAMPAIGN, FindingCategory.MALICIOUS_INFRASTRUCTURE}
        ),
        relationship=CorrelationRelationshipType.ASSOCIATED_WITH,
        title="Malicious infrastructure linked to a known campaign",
        same_subject=False,
        priority=70,
    ),
    CorrelationRule(
        id="malware_infrastructure_association",
        name="Known malware associated with malicious infrastructure",
        description=(
            "The investigation surfaced both a known malware family and malicious "
            "infrastructure (Threat Intelligence/Malware + Threat Intelligence)."
        ),
        category=CorrelationCategory.MALWARE_INFRASTRUCTURE_ASSOCIATION,
        required_categories=frozenset(
            {FindingCategory.MALWARE, FindingCategory.MALICIOUS_INFRASTRUCTURE}
        ),
        relationship=CorrelationRelationshipType.ASSOCIATED_WITH,
        title="Known malware associated with malicious infrastructure",
        same_subject=False,
        priority=70,
    ),
)

RULES: tuple[CorrelationRule, ...] = _SAME_SUBJECT_RULES + _CROSS_SUBJECT_RULES
"""The Phase 7.0 seed rule set (12 rules), byte-for-byte unchanged."""
