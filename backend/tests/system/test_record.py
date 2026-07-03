"""Unit tests bridging existing response objects into the metrics registry.

Every fixture here is a real (minimal) instance of the actual response model
each route already returns — these tests exercise the recording functions in
isolation, without going through the API layer.
"""

from __future__ import annotations

from datetime import UTC, datetime

from threatlens.ai.models import AIExplanation, AIStatus, FindingExplanation
from threatlens.detection.models import (
    DetectionArtifact,
    DetectionMetadata,
    DetectionPackage,
    DetectionTarget,
)
from threatlens.detection.types import DetectionLanguage
from threatlens.entities.types import EntityType
from threatlens.providers import AggregatedResult, ProviderSummary
from threatlens.providers.results import ResultStatus
from threatlens.reasoning.models import Confidence, ConfidenceBand, InvestigationSummary
from threatlens.system.metrics import MetricsRegistry
from threatlens.system.record import (
    record_ai_explanation,
    record_detection_generation,
    record_dkl_query,
    record_investigation,
)


def _aggregated(*providers: ProviderSummary) -> AggregatedResult:
    return AggregatedResult(
        entity_type=EntityType.IPV4, entity_value="8.8.8.8", providers=list(providers)
    )


def _summary(confidence: int = 80) -> InvestigationSummary:
    return InvestigationSummary(
        entity_type=EntityType.IPV4,
        entity_value="8.8.8.8",
        overall_confidence=Confidence(score=confidence, band=ConfidenceBand.HIGH),
        engine_version="1.0",
        generated_at=datetime.now(UTC),
    )


def _artifact(language: DetectionLanguage) -> DetectionArtifact:
    return DetectionArtifact(
        id=f"artifact-{language.value}",
        language=language,
        target=DetectionTarget(language=language),
        title=f"Detection ({language.value})",
    )


def _package(*languages: DetectionLanguage) -> DetectionPackage:
    return DetectionPackage(
        id="package-1",
        metadata=DetectionMetadata(
            engine_version="1.0",
            source_engine_version="1.0",
            entity_type=EntityType.IPV4,
            entity_value="8.8.8.8",
            generated_at=datetime.now(UTC),
        ),
        artifacts=tuple(_artifact(lang) for lang in languages),
        languages=languages,
    )


class TestRecordInvestigation:
    def test_counts_provider_success_and_failure(self) -> None:
        registry = MetricsRegistry()
        ti = _aggregated(
            ProviderSummary(provider="abuseipdb", status=ResultStatus.OK),
            ProviderSummary(provider="otx", status=ResultStatus.TIMEOUT),
        )
        kb = _aggregated(ProviderSummary(provider="mitre_attack", status=ResultStatus.NOT_FOUND))
        summary = _summary()

        record_investigation(
            registry, threat_intelligence=ti, knowledge=kb, summary=summary, duration_ms=42.0
        )

        assert registry.ti_providers["abuseipdb"].successes == 1
        assert registry.ti_providers["otx"].failures == 1
        # not_found is a reachable, successful call — just no record.
        assert registry.kb_providers["mitre_attack"].successes == 1
        assert registry.investigation_duration_ms.average == 42.0

    def test_records_findings_recommendations_and_confidence(self) -> None:
        registry = MetricsRegistry()
        empty = _aggregated()
        summary = _summary(confidence=75)

        record_investigation(
            registry, threat_intelligence=empty, knowledge=empty, summary=summary, duration_ms=10.0
        )

        assert registry.investigation_findings.average == 0
        assert registry.investigation_recommendations.average == 0
        assert registry.investigation_confidence.average == 75


class TestRecordAIExplanation:
    def test_success_counts_completion_chars(self) -> None:
        registry = MetricsRegistry()
        explanation = AIExplanation(
            status=AIStatus.OK,
            provider="ollama",
            model="qwen3:4b",
            executive_summary="short",
            technical_summary="also short",
            finding_explanations=[FindingExplanation(finding_id="f1", explanation="why")],
        )
        record_ai_explanation(
            registry, explanation=explanation, prompt_chars=1000, duration_ms=250.0
        )

        assert registry.ai.requests == 1
        assert registry.ai.successes == 1
        assert registry.ai_prompt_chars.average == 1000
        expected_completion = len("short") + len("also short") + len("why")
        assert registry.ai_completion_chars.average == expected_completion

    def test_error_status_counts_as_failure(self) -> None:
        registry = MetricsRegistry()
        explanation = AIExplanation(status=AIStatus.ERROR, provider="ollama", model=None)
        record_ai_explanation(registry, explanation=explanation, prompt_chars=100, duration_ms=5.0)
        assert registry.ai.failures == 1


class TestRecordDetectionGeneration:
    def test_counts_generated_artifacts_by_language(self) -> None:
        registry = MetricsRegistry()
        package = _package(DetectionLanguage.SIGMA, DetectionLanguage.YARA)
        record_detection_generation(registry, package=package, duration_ms=15.0)
        assert registry.detection_by_language == {"sigma": 1, "yara": 1}
        assert registry.detection_generation_ms.average == 15.0

    def test_empty_package_records_timing_without_error(self) -> None:
        registry = MetricsRegistry()
        record_detection_generation(registry, package=_package(), duration_ms=5.0)
        assert registry.detection_by_language == {}
        assert registry.detection_generation_ms.average == 5.0


class TestRecordDklQuery:
    def test_records_a_query(self) -> None:
        registry = MetricsRegistry()
        record_dkl_query(registry, duration_ms=3.0)
        assert registry.dkl_queries.requests == 1
        assert registry.dkl_queries.successes == 1
