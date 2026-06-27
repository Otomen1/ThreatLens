"""Tests for InvestigationContext and derived priority (Phase 3.1d).

Context influences only priority (finding + recommendation). It never changes
findings, severity, confidence, evidence, or recommendation content. The engine
behaves exactly as today under EMPTY context.
"""

from __future__ import annotations

from datetime import UTC, datetime

from threatlens.entities.models import Entity
from threatlens.entities.types import EntityType, ValidationStatus
from threatlens.providers.aggregation import AggregatedResult, ProviderSummary
from threatlens.providers.results import Reputation, ReputationLevel, ResultStatus
from threatlens.reasoning import (
    EMPTY_CONTEXT,
    AssetCriticality,
    Confidence,
    ConfidenceBand,
    Environment,
    InvestigationContext,
    Severity,
    derive_finding_priority,
    reason,
)

NOW = datetime(2024, 6, 1, tzinfo=UTC)


def _conf(band: ConfidenceBand = ConfidenceBand.HIGH) -> Confidence:
    return Confidence(score=70, band=band)


def _entity() -> Entity:
    return Entity(
        type=EntityType.IPV4,
        value="1.2.3.4",
        normalized_value="1.2.3.4",
        confidence=100,
        validation=ValidationStatus.VALID,
        possible_matches=[],
    )


def _malicious_ti() -> AggregatedResult:
    """A synthetic TI result that fires the Malicious Infrastructure rule offline."""
    return AggregatedResult(
        entity_type=EntityType.IPV4,
        entity_value="1.2.3.4",
        providers=[
            ProviderSummary(
                provider="abuseipdb",
                status=ResultStatus.OK,
                reputation=Reputation(level=ReputationLevel.MALICIOUS, score=95),
            )
        ],
    )


def _empty_kb() -> AggregatedResult:
    return AggregatedResult(entity_type=EntityType.IPV4, entity_value="1.2.3.4")


def _prod_critical() -> InvestigationContext:
    return InvestigationContext(
        criticality=AssetCriticality.CRITICAL,
        environment=Environment.PRODUCTION,
        internet_facing=True,
    )


# --------------------------------------------------------------------------- #
# Model & enums
# --------------------------------------------------------------------------- #


class TestModel:
    def test_empty_context_defaults(self) -> None:
        assert EMPTY_CONTEXT.criticality is AssetCriticality.UNKNOWN
        assert EMPTY_CONTEXT.environment is Environment.UNKNOWN
        assert EMPTY_CONTEXT.internet_facing is False
        assert EMPTY_CONTEXT.tags == []
        assert EMPTY_CONTEXT.attributes == {}

    def test_criticality_closed_set(self) -> None:
        assert {c.value for c in AssetCriticality} == {
            "unknown",
            "low",
            "medium",
            "high",
            "critical",
        }

    def test_environment_closed_set(self) -> None:
        assert {e.value for e in Environment} == {
            "unknown",
            "development",
            "test",
            "staging",
            "production",
        }


# --------------------------------------------------------------------------- #
# derive_finding_priority
# --------------------------------------------------------------------------- #


class TestDerivePriority:
    def test_empty_context_baseline(self) -> None:
        # HIGH severity (100) + HIGH confidence penalty (10) - no boost = 110.
        assert derive_finding_priority(Severity.HIGH, _conf(), EMPTY_CONTEXT) == 110

    def test_critical_asset_increases_urgency(self) -> None:
        ctx = InvestigationContext(criticality=AssetCriticality.CRITICAL)  # boost 40
        assert derive_finding_priority(Severity.HIGH, _conf(), ctx) == 70

    def test_internet_facing_increases_urgency(self) -> None:
        ctx = InvestigationContext(internet_facing=True)  # boost 20
        assert derive_finding_priority(Severity.HIGH, _conf(), ctx) == 90

    def test_production_increases_urgency(self) -> None:
        ctx = InvestigationContext(environment=Environment.PRODUCTION)  # boost 20
        assert derive_finding_priority(Severity.HIGH, _conf(), ctx) == 90

    def test_development_is_baseline(self) -> None:
        ctx = InvestigationContext(environment=Environment.DEVELOPMENT)  # no boost
        assert derive_finding_priority(Severity.HIGH, _conf(), ctx) == 110

    def test_low_criticality_is_baseline(self) -> None:
        ctx = InvestigationContext(criticality=AssetCriticality.LOW)  # no boost
        assert derive_finding_priority(Severity.HIGH, _conf(), ctx) == 110

    def test_confidence_refines_within_severity(self) -> None:
        high = derive_finding_priority(Severity.HIGH, _conf(ConfidenceBand.HIGH), EMPTY_CONTEXT)
        low = derive_finding_priority(Severity.HIGH, _conf(ConfidenceBand.LOW), EMPTY_CONTEXT)
        assert low > high  # less confident = less urgent

    def test_clamped_non_negative(self) -> None:
        ctx = _prod_critical()  # boost 80
        assert derive_finding_priority(Severity.CRITICAL, _conf(ConfidenceBand.VERY_HIGH), ctx) == 0

    def test_context_only_decreases_number(self) -> None:
        base = derive_finding_priority(
            Severity.MEDIUM, _conf(ConfidenceBand.MODERATE), EMPTY_CONTEXT
        )
        boosted = derive_finding_priority(
            Severity.MEDIUM, _conf(ConfidenceBand.MODERATE), _prod_critical()
        )
        assert boosted <= base

    def test_deterministic(self) -> None:
        ctx = InvestigationContext(criticality=AssetCriticality.HIGH)
        a = derive_finding_priority(Severity.HIGH, _conf(), ctx)
        b = derive_finding_priority(Severity.HIGH, _conf(), ctx)
        assert a == b


# --------------------------------------------------------------------------- #
# Engine integration: context affects priority only
# --------------------------------------------------------------------------- #


class TestEngineContext:
    def _both(self) -> tuple:
        ti, kb, entity = _malicious_ti(), _empty_kb(), _entity()
        empty = reason(entity, ti, kb, context=EMPTY_CONTEXT, now=NOW)
        prod = reason(entity, ti, kb, context=_prod_critical(), now=NOW)
        return empty, prod

    def test_findings_identical_except_priority(self) -> None:
        empty, prod = self._both()
        assert [f.id for f in empty.findings] == [f.id for f in prod.findings]
        assert [f.severity for f in empty.findings] == [f.severity for f in prod.findings]
        assert [f.confidence for f in empty.findings] == [f.confidence for f in prod.findings]
        assert [f.categories for f in empty.findings] == [f.categories for f in prod.findings]
        assert [f.evidence for f in empty.findings] == [f.evidence for f in prod.findings]

    def test_context_raises_finding_priority(self) -> None:
        empty, prod = self._both()
        assert prod.findings[0].priority < empty.findings[0].priority

    def test_recommendation_content_identical(self) -> None:
        empty, prod = self._both()
        assert [r.action for r in empty.recommendations] == [r.action for r in prod.recommendations]
        assert [r.rationale for r in empty.recommendations] == [
            r.rationale for r in prod.recommendations
        ]

    def test_recommendation_priority_inherits_finding_priority(self) -> None:
        empty, prod = self._both()
        f_empty, f_prod = empty.findings[0], prod.findings[0]
        delta = f_empty.priority - f_prod.priority
        assert delta > 0
        empty_by_action = {r.action: r.priority for r in f_empty.recommendations}
        prod_by_action = {r.action: r.priority for r in f_prod.recommendations}
        # Every recommendation shifts by exactly the finding-priority delta.
        for action, prio in empty_by_action.items():
            assert prio - prod_by_action[action] == delta

    def test_development_equals_empty(self) -> None:
        ti, kb, entity = _malicious_ti(), _empty_kb(), _entity()
        empty = reason(entity, ti, kb, context=EMPTY_CONTEXT, now=NOW)
        dev = reason(
            entity,
            ti,
            kb,
            context=InvestigationContext(environment=Environment.DEVELOPMENT),
            now=NOW,
        )
        assert empty.findings[0].priority == dev.findings[0].priority

    def test_default_context_is_empty(self) -> None:
        ti, kb, entity = _malicious_ti(), _empty_kb(), _entity()
        assert reason(entity, ti, kb, now=NOW) == reason(
            entity, ti, kb, context=EMPTY_CONTEXT, now=NOW
        )

    def test_deterministic_under_context(self) -> None:
        ti, kb, entity = _malicious_ti(), _empty_kb(), _entity()
        ctx = _prod_critical()
        assert reason(entity, ti, kb, context=ctx, now=NOW) == reason(
            entity, ti, kb, context=ctx, now=NOW
        )
