"""Tests for CorrelationService — a thin, deterministic wrapper over the engine."""

from __future__ import annotations

from threatlens.correlation.engine import correlate
from threatlens.correlation.registry import CorrelationRegistry, build_default_registry
from threatlens.correlation.service import CorrelationService
from threatlens.reasoning.models import FindingCategory as FC
from threatlens.reasoning.models import InvestigationSummary

from .factories import finding, summary


def _malicious_exposed() -> InvestigationSummary:
    return summary(
        [finding("fnd_1", {FC.MALICIOUS_INFRASTRUCTURE}), finding("fnd_2", {FC.EXPOSURE})]
    )


class TestCorrelationService:
    def test_default_service_uses_the_seed_registry(self) -> None:
        service = CorrelationService()
        assert len(service.registry) == 12

    def test_correlate_matches_the_engine(self) -> None:
        service = CorrelationService()
        source = _malicious_exposed()
        assert service.correlate(source) == correlate(source, registry=service.registry)

    def test_correlate_is_deterministic(self) -> None:
        service = CorrelationService()
        assert service.correlate(_malicious_exposed()) == service.correlate(_malicious_exposed())

    def test_empty_registry_yields_no_observations(self) -> None:
        service = CorrelationService(CorrelationRegistry())
        result = service.correlate(_malicious_exposed())
        assert result.observations == ()
        assert result.statistics.rules_evaluated == 0

    def test_does_not_mutate_the_input(self) -> None:
        service = CorrelationService(build_default_registry())
        source = _malicious_exposed()
        snapshot = source.model_dump_json()
        service.correlate(source)
        assert source.model_dump_json() == snapshot
