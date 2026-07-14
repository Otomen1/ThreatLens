"""Infrastructure correlation rules: MALICIOUS_INFRASTRUCTURE, EXPOSURE,
REPUTATION, and MISCONFIGURATION combined with each other and with the
disposition categories (CONTESTED, ACTION_REQUIRED, INFORMATIONAL).

The Phase 7.0 seed set already covers malicious+exposed, malicious+reputation,
and exposed+misconfigured (same-subject). This module fills in the remaining
pairs within this four-category cluster, plus the disposition combinations that
flag *which* infrastructure findings are still contested, actionable, or
low-priority — all same-subject: infrastructure signals are host/asset-bound.
"""

from __future__ import annotations

from ...reasoning.models import FindingCategory as FC
from ..models import CorrelationCategory as Cat
from ..models import CorrelationRelationshipType as Rel
from ..models import CorrelationRule

RULES: tuple[CorrelationRule, ...] = (
    CorrelationRule(
        id="malicious_infrastructure_misconfiguration",
        name="Malicious infrastructure with a misconfigured service",
        description=(
            "An entity flagged as malicious infrastructure that also runs a "
            "misconfigured service (Threat Intelligence + misconfiguration)."
        ),
        category=Cat.MALICIOUS_INFRASTRUCTURE_WEAKNESS_LINK,
        required_categories=frozenset({FC.MALICIOUS_INFRASTRUCTURE, FC.MISCONFIGURATION}),
        relationship=Rel.ASSOCIATED_WITH,
        title="Malicious infrastructure with a misconfigured service",
        priority=101,
    ),
    CorrelationRule(
        id="reputation_exposed_service",
        name="Independently corroborated reputation signal on an exposed service",
        description=(
            "An exposed internet-facing service on an entity that also carries "
            "an independent reputation signal (Exposure + reputation)."
        ),
        category=Cat.CORROBORATED_REPUTATION_SIGNAL,
        required_categories=frozenset({FC.REPUTATION, FC.EXPOSURE}),
        relationship=Rel.ASSOCIATED_WITH,
        title="Independently corroborated reputation signal on an exposed service",
        priority=102,
    ),
    CorrelationRule(
        id="reputation_misconfigured_service",
        name="Reputation signal on a misconfigured service",
        description=(
            "A misconfigured service on this entity that also carries an "
            "independent reputation signal (Misconfiguration + reputation)."
        ),
        category=Cat.CORROBORATED_REPUTATION_SIGNAL,
        required_categories=frozenset({FC.REPUTATION, FC.MISCONFIGURATION}),
        relationship=Rel.ASSOCIATED_WITH,
        title="Reputation signal on a misconfigured service",
        priority=103,
    ),
    CorrelationRule(
        id="malicious_infrastructure_contested",
        name="Malicious-infrastructure verdict contested across sources",
        description=(
            "An entity flagged as malicious infrastructure whose disposition is "
            "also flagged contested — sources disagree on this specific finding "
            "(Threat Intelligence + contested)."
        ),
        category=Cat.FINDING_CONTESTED,
        required_categories=frozenset({FC.MALICIOUS_INFRASTRUCTURE, FC.CONTESTED}),
        relationship=Rel.CO_OCCURS_WITH,
        title="Malicious-infrastructure verdict contested across sources",
        priority=104,
    ),
    CorrelationRule(
        id="exposure_contested",
        name="Exposed service with a contested disposition",
        description=(
            "An exposed internet-facing service whose disposition is flagged "
            "contested — sources disagree on this specific finding (Exposure + "
            "contested)."
        ),
        category=Cat.FINDING_CONTESTED,
        required_categories=frozenset({FC.EXPOSURE, FC.CONTESTED}),
        relationship=Rel.CO_OCCURS_WITH,
        title="Exposed service with a contested disposition",
        priority=105,
    ),
    CorrelationRule(
        id="reputation_contested",
        name="Reputation signal with a contested disposition",
        description=(
            "A reputation-based finding on this entity whose disposition is "
            "also flagged contested (Reputation + contested)."
        ),
        category=Cat.FINDING_CONTESTED,
        required_categories=frozenset({FC.REPUTATION, FC.CONTESTED}),
        relationship=Rel.CO_OCCURS_WITH,
        title="Reputation signal with a contested disposition",
        priority=106,
    ),
    CorrelationRule(
        id="malicious_infrastructure_action_required",
        name="Malicious infrastructure flagged for required action",
        description=(
            "An entity flagged as malicious infrastructure whose disposition is "
            "also flagged action-required (Threat Intelligence + "
            "action-required)."
        ),
        category=Cat.FINDING_REQUIRES_ACTION,
        required_categories=frozenset({FC.MALICIOUS_INFRASTRUCTURE, FC.ACTION_REQUIRED}),
        relationship=Rel.CO_OCCURS_WITH,
        title="Malicious infrastructure flagged for required action",
        priority=107,
    ),
    CorrelationRule(
        id="misconfiguration_action_required",
        name="Misconfigured service flagged for required action",
        description=(
            "A misconfigured service on this entity whose disposition is also "
            "flagged action-required (Misconfiguration + action-required)."
        ),
        category=Cat.FINDING_REQUIRES_ACTION,
        required_categories=frozenset({FC.MISCONFIGURATION, FC.ACTION_REQUIRED}),
        relationship=Rel.CO_OCCURS_WITH,
        title="Misconfigured service flagged for required action",
        priority=108,
    ),
    CorrelationRule(
        id="malicious_infrastructure_informational",
        name="Malicious-infrastructure signal assessed as low-actionability",
        description=(
            "An entity flagged as malicious infrastructure whose disposition is "
            "also flagged informational — a down-weighting signal worth "
            "surfacing separately from an unresolved (contested) disagreement "
            "(Threat Intelligence + informational)."
        ),
        category=Cat.FINDING_LOW_ACTIONABILITY,
        required_categories=frozenset({FC.MALICIOUS_INFRASTRUCTURE, FC.INFORMATIONAL}),
        relationship=Rel.CO_OCCURS_WITH,
        title="Malicious-infrastructure signal assessed as low-actionability",
        priority=109,
    ),
)
