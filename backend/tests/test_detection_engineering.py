"""Detection Engineering Framework tests (Phase 4.0).

Covers the pure engine (purity, determinism, inherited timestamp), content-
addressed identity (timestamp-independent), the registry and template
infrastructure, serialization/immutability, config, and the API contract. A
fake generator exercises the full registry → engine → package pipeline even
though no generators ship by default.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from threatlens.api.app import app
from threatlens.detection import (
    DETECTION_ENGINE_VERSION,
    DetectionArtifact,
    DetectionCategory,
    DetectionGenerator,
    DetectionLanguage,
    DetectionPackage,
    DetectionRegistry,
    DetectionSettings,
    DetectionSeverity,
    DetectionTarget,
    DetectionTemplate,
    DuplicateDetectionGeneratorError,
    DuplicateDetectionTemplateError,
    TemplateRegistry,
    apply_template,
    build_default_registry,
    build_default_template_registry,
    compute_artifact_id,
    generate,
)
from threatlens.entities.types import EntityType
from threatlens.reasoning import (
    Confidence,
    ConfidenceBand,
    Finding,
    FindingCategory,
    InvestigationSummary,
    Severity,
)

# --------------------------------------------------------------------------- #
# Fixtures / helpers
# --------------------------------------------------------------------------- #

_NOW = datetime(2024, 1, 1, tzinfo=UTC)


def _finding(fid: str = "fnd_1", severity: Severity = Severity.HIGH) -> Finding:
    return Finding(
        id=fid,
        title="Example finding",
        categories=frozenset({FindingCategory.REPUTATION}),
        subject_type=EntityType.IPV4,
        subject_value="8.8.8.8",
        severity=severity,
        confidence=Confidence(score=50, band=ConfidenceBand.MODERATE),
    )


def _summary(
    *,
    findings: Sequence[Finding] = (),
    posture: Severity = Severity.HIGH,
    generated_at: datetime = _NOW,
    engine_version: str = "1.0",
    entity_value: str = "8.8.8.8",
) -> InvestigationSummary:
    return InvestigationSummary(
        entity_type=EntityType.IPV4,
        entity_value=entity_value,
        posture=posture,
        overall_confidence=Confidence(score=50, band=ConfidenceBand.MODERATE),
        findings=list(findings),
        engine_version=engine_version,
        generated_at=generated_at,
    )


class _FakeGenerator(DetectionGenerator):
    """A minimal generator for pipeline tests (never ships in production)."""

    def __init__(
        self,
        *,
        name: str = "fake",
        language: DetectionLanguage = DetectionLanguage.SIGMA,
        priority: int = 100,
        count: int = 1,
    ) -> None:
        self._name = name
        self._language = language
        self._priority = priority
        self._count = count

    @property
    def name(self) -> str:
        return self._name

    @property
    def language(self) -> DetectionLanguage:
        return self._language

    @property
    def priority(self) -> int:
        return self._priority

    def generate(self, summary: InvestigationSummary) -> Sequence[DetectionArtifact]:
        template = DetectionTemplate(
            id=f"{self._name}-tmpl",
            name=self._name,
            language=self._language,
            target=DetectionTarget(language=self._language),
            category=DetectionCategory.NETWORK,
        )
        finding_ids = [f.id for f in summary.findings]
        return [
            apply_template(
                template,
                title=f"artifact {i}",
                content=f"rule-{i}",
                severity=DetectionSeverity.HIGH,
                source_finding_ids=finding_ids,
            )
            for i in range(self._count)
        ]


# --------------------------------------------------------------------------- #
# Pure function: purity, determinism, empty package
# --------------------------------------------------------------------------- #


def test_empty_registry_yields_empty_package() -> None:
    pkg = generate(_summary(findings=[_finding()]), registry=DetectionRegistry())
    assert pkg.is_empty
    assert pkg.artifacts == ()
    assert pkg.languages == ()


def test_generation_is_deterministic() -> None:
    summary = _summary(findings=[_finding("fnd_a"), _finding("fnd_b")])
    assert generate(summary) == generate(summary)


def test_generate_does_not_mutate_summary() -> None:
    summary = _summary(findings=[_finding()])
    before = summary.model_dump_json()
    generate(summary)
    assert summary.model_dump_json() == before  # pure consumer — read-only


def test_metadata_is_inherited_from_summary() -> None:
    summary = _summary(findings=[_finding(), _finding("fnd_2")], posture=Severity.CRITICAL)
    meta = generate(summary).metadata
    assert meta.engine_version == DETECTION_ENGINE_VERSION
    assert meta.source_engine_version == summary.engine_version
    assert meta.generated_at == summary.generated_at  # never reads the wall clock
    assert meta.source_finding_count == 2
    assert meta.source_posture == DetectionSeverity.CRITICAL  # copied, not recomputed
    assert generate(summary).source_finding_ids == ("fnd_1", "fnd_2")


# --------------------------------------------------------------------------- #
# Identity: content-addressed and timestamp-independent
# --------------------------------------------------------------------------- #


def test_package_id_excludes_timestamp() -> None:
    early = _summary(findings=[_finding()], generated_at=datetime(2024, 1, 1, tzinfo=UTC))
    late = _summary(findings=[_finding()], generated_at=datetime(2025, 6, 6, tzinfo=UTC))
    assert generate(early).id == generate(late).id  # id ignores generated_at
    assert generate(early).metadata.generated_at != generate(late).metadata.generated_at


def test_package_id_changes_with_findings_and_prefix() -> None:
    one = generate(_summary(findings=[_finding("fnd_a")]))
    two = generate(_summary(findings=[_finding("fnd_b")]))
    assert one.id != two.id
    assert one.id.startswith("pkg_")


def test_artifact_id_is_content_addressed() -> None:
    template = DetectionTemplate(
        id="t",
        name="t",
        language=DetectionLanguage.SIGMA,
        target=DetectionTarget(language=DetectionLanguage.SIGMA),
        category=DetectionCategory.NETWORK,
    )
    base = apply_template(template, title="A", content="rule", source_finding_ids=["fnd_1"])
    same_content = apply_template(template, title="B", content="rule", source_finding_ids=["fnd_1"])
    other = apply_template(template, title="A", content="other", source_finding_ids=["fnd_1"])
    assert base.id == same_content.id  # title is not part of identity
    assert base.id != other.id  # content is
    assert base.id.startswith("det_")


def test_compute_artifact_id_ignores_finding_order() -> None:
    a = compute_artifact_id(
        language=DetectionLanguage.YARA,
        target_platform="generic",
        category=DetectionCategory.FILE,
        content="x",
        rule_id=None,
        source_finding_ids=["fnd_b", "fnd_a"],
    )
    b = compute_artifact_id(
        language=DetectionLanguage.YARA,
        target_platform="generic",
        category=DetectionCategory.FILE,
        content="x",
        rule_id=None,
        source_finding_ids=["fnd_a", "fnd_b"],
    )
    assert a == b


# --------------------------------------------------------------------------- #
# Registry
# --------------------------------------------------------------------------- #


def test_default_registry_has_sigma_generator() -> None:
    # Phase 4.1 registers the Sigma generator; a fresh registry is still the seam.
    registry = build_default_registry()
    assert [g.name for g in registry.generators] == ["sigma"]
    assert registry.languages == (DetectionLanguage.SIGMA,)
    assert len(DetectionRegistry()) == 0


def test_registry_register_get_and_duplicate() -> None:
    registry = DetectionRegistry()
    registry.register(_FakeGenerator(name="a"))
    assert "a" in registry
    assert registry.get("a") is not None
    assert len(registry) == 1
    with pytest.raises(DuplicateDetectionGeneratorError):
        registry.register(_FakeGenerator(name="a"))


def test_registry_orders_by_priority_then_name() -> None:
    registry = DetectionRegistry()
    registry.register(_FakeGenerator(name="z", priority=10))
    registry.register(_FakeGenerator(name="a", priority=10))
    registry.register(_FakeGenerator(name="m", priority=5))
    assert [g.name for g in registry.generators] == ["m", "a", "z"]


# --------------------------------------------------------------------------- #
# End-to-end pipeline via a fake generator
# --------------------------------------------------------------------------- #


def test_pipeline_with_generator_produces_artifacts() -> None:
    registry = DetectionRegistry()
    registry.register(_FakeGenerator(name="sig", language=DetectionLanguage.SIGMA, count=2))
    summary = _summary(findings=[_finding("fnd_a"), _finding("fnd_b")])

    pkg = generate(summary, registry=registry)
    assert not pkg.is_empty
    assert len(pkg.artifacts) == 2
    assert pkg.languages == (DetectionLanguage.SIGMA,)
    assert all(a.source_finding_ids == ("fnd_a", "fnd_b") for a in pkg.artifacts)
    # Deterministic, and distinct from the empty (default-registry) package.
    assert generate(summary, registry=registry) == pkg
    assert generate(summary).id != pkg.id


def test_pipeline_orders_multiple_languages() -> None:
    registry = DetectionRegistry()
    registry.register(_FakeGenerator(name="y", language=DetectionLanguage.YARA))
    registry.register(_FakeGenerator(name="s", language=DetectionLanguage.SIGMA))
    pkg = generate(_summary(findings=[_finding()]), registry=registry)
    assert pkg.languages == (DetectionLanguage.SIGMA, DetectionLanguage.YARA)  # sorted


# --------------------------------------------------------------------------- #
# Templates
# --------------------------------------------------------------------------- #


def test_default_template_registry_is_empty() -> None:
    assert len(build_default_template_registry()) == 0


def test_template_registry_register_and_duplicate() -> None:
    registry = TemplateRegistry()
    template = DetectionTemplate(
        id="t1",
        name="t1",
        language=DetectionLanguage.SIGMA,
        target=DetectionTarget(language=DetectionLanguage.SIGMA),
    )
    registry.register(template)
    assert registry.get("t1") is template
    assert len(registry) == 1
    with pytest.raises(DuplicateDetectionTemplateError):
        registry.register(template)


def test_apply_template_copies_template_shape() -> None:
    template = DetectionTemplate(
        id="t",
        name="t",
        language=DetectionLanguage.YARA,
        target=DetectionTarget(language=DetectionLanguage.YARA, platform="generic"),
        category=DetectionCategory.FILE,
    )
    artifact = apply_template(
        template,
        title="Example",
        content="rule x {}",
        severity=DetectionSeverity.MEDIUM,
        source_finding_ids=["fnd_1"],
    )
    assert artifact.language == DetectionLanguage.YARA
    assert artifact.category == DetectionCategory.FILE
    assert artifact.severity == DetectionSeverity.MEDIUM
    assert artifact.validation.status.value == "unvalidated"  # no validators yet


# --------------------------------------------------------------------------- #
# Serialization & immutability
# --------------------------------------------------------------------------- #


def test_package_round_trips_through_json() -> None:
    registry = DetectionRegistry()
    registry.register(_FakeGenerator(count=1))
    pkg = generate(_summary(findings=[_finding()]), registry=registry)
    assert DetectionPackage.model_validate_json(pkg.model_dump_json()) == pkg


def test_package_is_frozen() -> None:
    pkg = generate(_summary())
    with pytest.raises(ValidationError):
        pkg.id = "mutated"  # type: ignore[misc]


# --------------------------------------------------------------------------- #
# Config
# --------------------------------------------------------------------------- #


def test_config_defaults() -> None:
    settings = DetectionSettings.from_env({})
    assert settings.enabled is True
    assert settings.languages == frozenset()


def test_config_parses_env() -> None:
    settings = DetectionSettings.from_env(
        {"DETECTION_ENABLED": "false", "DETECTION_LANGUAGES": "sigma, yara, bogus"}
    )
    assert settings.enabled is False
    assert settings.languages == frozenset({DetectionLanguage.SIGMA, DetectionLanguage.YARA})


# --------------------------------------------------------------------------- #
# API contract
# --------------------------------------------------------------------------- #


class TestDetectionAPI:
    client = TestClient(app)

    def _summary_for(self, query: str) -> dict[str, Any]:
        body = self.client.post("/api/v1/investigate", json={"query": query}).json()
        return body["investigation_summary"]

    def test_returns_empty_package(self) -> None:
        summary = self._summary_for("T1059")
        res = self.client.post("/api/v1/detections", json=summary)
        assert res.status_code == 200
        pkg = res.json()
        assert pkg["artifacts"] == []
        assert pkg["id"].startswith("pkg_")
        assert pkg["metadata"]["source_engine_version"] == summary["engine_version"]
        assert pkg["source_finding_ids"] == [f["id"] for f in summary["findings"]]

    def test_is_deterministic_over_http(self) -> None:
        summary = self._summary_for("T1059")
        first = self.client.post("/api/v1/detections", json=summary).json()
        second = self.client.post("/api/v1/detections", json=summary).json()
        assert first == second

    def test_invalid_body_is_rejected(self) -> None:
        assert self.client.post("/api/v1/detections", json={"nope": 1}).status_code == 422

    def test_detection_does_not_alter_the_investigation(self) -> None:
        before = self._summary_for("T1059")
        self.client.post("/api/v1/detections", json=before)
        after = self._summary_for("T1059")
        # The reasoning output is deterministic and detection is a pure consumer:
        # findings, confidence, and recommendations are unchanged.
        assert before["findings"] == after["findings"]
        assert before["overall_confidence"] == after["overall_confidence"]
        assert before["recommendations"] == after["recommendations"]
