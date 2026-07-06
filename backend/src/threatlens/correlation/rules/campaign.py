"""Campaign correlation rules: CAMPAIGN combined with every domain category not
already covered by the Phase 7.0 seed set.

The seed set covers campaign+infrastructure (cross-subject only). This module
adds the same-subject variant, plus campaign paired with malware and technique
(cross-subject — a campaign label and a malware/technique finding are commonly
on different subjects) and campaign paired with vulnerability, exposure,
known-exploited, and action-required (same-subject: these describe the
campaign's own infrastructure).
"""

from __future__ import annotations

from ...reasoning.models import FindingCategory as FC
from ..models import CorrelationCategory as Cat
from ..models import CorrelationRelationshipType as Rel
from ..models import CorrelationRule

RULES: tuple[CorrelationRule, ...] = (
    CorrelationRule(
        id="campaign_infrastructure_colocated",
        name="Known campaign and malicious infrastructure observed on the same entity",
        description=(
            "A known campaign and malicious infrastructure observed on the "
            "*same* subject — a tighter binding than the seed set's "
            "cross-subject campaign+infrastructure association."
        ),
        category=Cat.CAMPAIGN_INFRASTRUCTURE_COLOCATED,
        required_categories=frozenset({FC.CAMPAIGN, FC.MALICIOUS_INFRASTRUCTURE}),
        relationship=Rel.ASSOCIATED_WITH,
        title="Known campaign and malicious infrastructure observed on the same entity",
        priority=141,
    ),
    CorrelationRule(
        id="campaign_malware",
        name="Known campaign associated with known malware",
        description=(
            "The investigation surfaced both a known campaign and a known "
            "malware family (Knowledge/Campaign + Threat Intelligence/Malware)."
        ),
        category=Cat.MALWARE_CAMPAIGN_LINK,
        required_categories=frozenset({FC.CAMPAIGN, FC.MALWARE}),
        relationship=Rel.ASSOCIATED_WITH,
        title="Known campaign associated with known malware",
        same_subject=False,
        priority=142,
    ),
    CorrelationRule(
        id="campaign_attack_pattern",
        name="Known campaign mapped to an observed ATT&CK technique",
        description=(
            "The investigation surfaced both a known campaign and an ATT&CK "
            "technique (Knowledge/Campaign + Knowledge/ATT&CK)."
        ),
        category=Cat.CAMPAIGN_TECHNIQUE_LINK,
        required_categories=frozenset({FC.CAMPAIGN, FC.ATTACK_PATTERN}),
        relationship=Rel.MAPPED_TO,
        title="Known campaign mapped to an observed ATT&CK technique",
        same_subject=False,
        priority=143,
    ),
    CorrelationRule(
        id="campaign_vulnerability",
        name="Campaign infrastructure carrying a known vulnerability",
        description=(
            "A campaign-linked finding on an entity that also carries a known "
            "vulnerability (Knowledge/Campaign + Knowledge/Vulnerability)."
        ),
        category=Cat.CAMPAIGN_ASSET_ASSOCIATION,
        required_categories=frozenset({FC.CAMPAIGN, FC.VULNERABILITY}),
        relationship=Rel.ASSOCIATED_WITH,
        title="Campaign infrastructure carrying a known vulnerability",
        priority=144,
    ),
    CorrelationRule(
        id="campaign_exposure",
        name="Campaign infrastructure with exposed services",
        description=(
            "A campaign-linked finding on an entity that also has an exposed "
            "internet-facing service (Knowledge/Campaign + Exposure)."
        ),
        category=Cat.CAMPAIGN_ASSET_ASSOCIATION,
        required_categories=frozenset({FC.CAMPAIGN, FC.EXPOSURE}),
        relationship=Rel.ASSOCIATED_WITH,
        title="Campaign infrastructure with exposed services",
        priority=145,
    ),
    CorrelationRule(
        id="campaign_known_exploited",
        name="Campaign infrastructure affected by a known-exploited vulnerability",
        description=(
            "A campaign-linked finding on an entity that also carries a "
            "known-exploited vulnerability (Knowledge/Campaign + "
            "known-exploited)."
        ),
        category=Cat.CAMPAIGN_ASSET_ASSOCIATION,
        required_categories=frozenset({FC.CAMPAIGN, FC.KNOWN_EXPLOITED}),
        relationship=Rel.EXPLOITS,
        title="Campaign infrastructure affected by a known-exploited vulnerability",
        priority=146,
    ),
    CorrelationRule(
        id="campaign_action_required",
        name="Campaign-linked infrastructure flagged for required action",
        description=(
            "A campaign-linked finding on this entity whose disposition is "
            "also flagged action-required (Knowledge/Campaign + "
            "action-required)."
        ),
        category=Cat.FINDING_REQUIRES_ACTION,
        required_categories=frozenset({FC.CAMPAIGN, FC.ACTION_REQUIRED}),
        relationship=Rel.CO_OCCURS_WITH,
        title="Campaign-linked infrastructure flagged for required action",
        priority=147,
    ),
)
