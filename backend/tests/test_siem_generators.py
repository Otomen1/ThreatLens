"""SIEM detection generator tests (Phase 4.4).

Covers all five platforms (Splunk SPL, Sentinel KQL, Elastic ES|QL, Chronicle
YARA-L, QRadar AQL): registration, every supported IOC type, unsupported
rejection, native syntax, complete provenance metadata, parser-level validation,
determinism, timestamp-independent stable ids, serialization, golden snapshots,
and the API contract. Generators consume only Finding objects.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

import pytest
from fastapi.testclient import TestClient

from threatlens.api.app import app
from threatlens.detection import (
    ChronicleGenerator,
    DetectionPackage,
    ElasticGenerator,
    QRadarGenerator,
    SentinelGenerator,
    SplunkGenerator,
    build_default_registry,
    generate,
)
from threatlens.entities.types import EntityType
from threatlens.providers.aggregation import AttributedRelationship
from threatlens.providers.results import (
    Relationship,
    RelationshipTargetType,
    RelationshipType,
)
from threatlens.reasoning import (
    Confidence,
    ConfidenceBand,
    Finding,
    FindingCategory,
    InvestigationSummary,
    Severity,
)

_NOW = datetime(2024, 1, 1, tzinfo=UTC)
_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

# (generator class, name, language value, required native tokens)
_GENERATORS = [
    (SplunkGenerator, "splunk", "splunk_spl", ("index=",)),
    (SentinelGenerator, "sentinel", "sentinel_kql", ("| where",)),
    (ElasticGenerator, "elastic", "elastic_esql", ("FROM ", "WHERE ")),
    (ChronicleGenerator, "chronicle", "chronicle_yara_l", ("rule ", "events:", "condition:")),
    (QRadarGenerator, "qradar", "qradar_aql", ("SELECT ", "FROM ")),
]
_IDS = [g[1] for g in _GENERATORS]

# All seven supported IOC subject types.
_SUPPORTED_IOCS = [
    (EntityType.IPV4, "45.155.205.233"),
    (EntityType.DOMAIN, "evil.example.net"),
    (EntityType.URL, "http://evil.example.net/gate.php?id=1"),
    (EntityType.SHA256, _SHA256),
    (EntityType.PROCESS_NAME, "powershell.exe"),
    (EntityType.REGISTRY_KEY, "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
    (EntityType.POWERSHELL_COMMAND, "IEX (New-Object Net.WebClient).DownloadString('x')"),
]

_REQUIRED_META = {
    "detection_id",
    "generator",
    "platform",
    "finding_ids",
    "severity",
    "confidence",
    "ioc_type",
    "ioc_value",
    "generated_at",
    "engine_version",
    "rule_id",
}

_GOLDEN = {
    "splunk": ("det_abe526c90847be42", "82814aaa80c39cf1"),
    "sentinel": ("det_26b8de7a287b08b9", "d5a0910994594ce5"),
    "elastic": ("det_18fcb90a943d478a", "59c4e96c8051dc4f"),
    "chronicle": ("det_9de4f1dc8670bd50", "89e999e96c74e7d8"),
    "qradar": ("det_8f5460d85e49654f", "5982f8158070d1c9"),
}


def _attack(technique: str) -> AttributedRelationship:
    return AttributedRelationship(
        relationship=Relationship(
            relationship=RelationshipType.USES,
            target_type=RelationshipTargetType.ATTACK_PATTERN,
            target_value=technique,
        ),
        sources=["mitre_attack"],
    )


def _finding(
    *,
    fid: str = "fnd_1",
    subject_type: EntityType = EntityType.IPV4,
    subject_value: str = "45.155.205.233",
    severity: Severity = Severity.HIGH,
    categories: frozenset[FindingCategory] = frozenset({FindingCategory.MALICIOUS_INFRASTRUCTURE}),
    sources: Sequence[str] = ("abuseipdb",),
    relationships: Sequence[AttributedRelationship] = (),
) -> Finding:
    return Finding(
        id=fid,
        title="Example finding",
        categories=categories,
        subject_type=subject_type,
        subject_value=subject_value,
        severity=severity,
        confidence=Confidence(score=90, band=ConfidenceBand.VERY_HIGH),
        sources=list(sources),
        relationships=list(relationships),
    )


def _summary(findings: Sequence[Finding], *, generated_at: datetime = _NOW) -> InvestigationSummary:
    first = findings[0]
    return InvestigationSummary(
        entity_type=first.subject_type,
        entity_value=first.subject_value,
        posture=Severity.HIGH,
        overall_confidence=Confidence(score=90, band=ConfidenceBand.VERY_HIGH),
        findings=list(findings),
        engine_version="1.0",
        generated_at=generated_at,
    )


def _rules(gen: Any, findings: Sequence[Finding], *, generated_at: datetime = _NOW) -> list[Any]:
    return list(gen.generate(_summary(findings, generated_at=generated_at)))


# --------------------------------------------------------------------------- #
# Registration
# --------------------------------------------------------------------------- #


def test_all_siem_generators_registered() -> None:
    names = {g.name for g in build_default_registry().generators}
    assert {"splunk", "sentinel", "elastic", "chronicle", "qradar"} <= names


# --------------------------------------------------------------------------- #
# Supported IOC mappings + native syntax + validation
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(("gen_cls", "name", "lang", "tokens"), _GENERATORS, ids=_IDS)
def test_each_generator_handles_every_supported_ioc(
    gen_cls: Any, name: str, lang: str, tokens: tuple[str, ...]
) -> None:
    for subject_type, value in _SUPPORTED_IOCS:
        artifacts = _rules(gen_cls(), [_finding(subject_type=subject_type, subject_value=value)])
        assert len(artifacts) == 1, (name, subject_type)
        artifact = artifacts[0]
        assert artifact.language.value == lang
        assert artifact.validation.status.value == "valid"
        for token in tokens:
            assert token in artifact.content, (name, subject_type, token)


@pytest.mark.parametrize(("gen_cls", "name", "lang", "tokens"), _GENERATORS, ids=_IDS)
def test_unsupported_subjects_yield_no_rule(
    gen_cls: Any, name: str, lang: str, tokens: tuple[str, ...]
) -> None:
    for subject_type, value in [
        (EntityType.CWE, "CWE-79"),
        (EntityType.CAPEC, "CAPEC-66"),
        (EntityType.THREAT_ACTOR, "APT28"),
        (EntityType.MITRE_TECHNIQUE, "T1059"),
    ]:
        assert _rules(gen_cls(), [_finding(subject_type=subject_type, subject_value=value)]) == []


@pytest.mark.parametrize(("gen_cls", "name", "lang", "tokens"), _GENERATORS, ids=_IDS)
def test_informational_and_bad_hash_skipped(
    gen_cls: Any, name: str, lang: str, tokens: tuple[str, ...]
) -> None:
    assert _rules(gen_cls(), [_finding(severity=Severity.INFORMATIONAL)]) == []
    assert _rules(gen_cls(), [_finding(subject_type=EntityType.MD5, subject_value="xyz")]) == []


# --------------------------------------------------------------------------- #
# Metadata completeness
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(("gen_cls", "name", "lang", "tokens"), _GENERATORS, ids=_IDS)
def test_metadata_is_complete(
    gen_cls: Any, name: str, lang: str, tokens: tuple[str, ...]
) -> None:
    artifact = _rules(gen_cls(), [_finding(fid="fnd_x", relationships=[_attack("T1071")])])[0]
    assert set(artifact.metadata) >= _REQUIRED_META
    assert artifact.metadata["detection_id"] == artifact.id
    assert artifact.metadata["generator"] == name
    assert artifact.metadata["finding_ids"] == "fnd_x"
    assert artifact.metadata["mitre"] == "T1071"
    # The provenance is embedded in the query text too.
    assert artifact.id in artifact.content
    assert "fnd_x" in artifact.content


# --------------------------------------------------------------------------- #
# Determinism & stable ids
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(("gen_cls", "name", "lang", "tokens"), _GENERATORS, ids=_IDS)
def test_deterministic(gen_cls: Any, name: str, lang: str, tokens: tuple[str, ...]) -> None:
    findings = [_finding()]
    assert _rules(gen_cls(), findings) == _rules(gen_cls(), findings)


@pytest.mark.parametrize(("gen_cls", "name", "lang", "tokens"), _GENERATORS, ids=_IDS)
def test_ids_are_timestamp_independent(
    gen_cls: Any, name: str, lang: str, tokens: tuple[str, ...]
) -> None:
    early = _rules(gen_cls(), [_finding()], generated_at=datetime(2024, 1, 1, tzinfo=UTC))[0]
    late = _rules(gen_cls(), [_finding()], generated_at=datetime(2030, 9, 9, tzinfo=UTC))[0]
    assert early.id == late.id  # identity excludes the timestamp
    assert early.rule_id == late.rule_id
    assert "2024-01-01" in early.content and "2030-09-09" in late.content


def test_package_id_stable_with_siem_active() -> None:
    a = generate(_summary([_finding()], generated_at=datetime(2024, 1, 1, tzinfo=UTC)))
    b = generate(_summary([_finding()], generated_at=datetime(2030, 1, 1, tzinfo=UTC)))
    assert a.id == b.id


# --------------------------------------------------------------------------- #
# Serialization
# --------------------------------------------------------------------------- #


def test_package_round_trips_through_json() -> None:
    finding = _finding(subject_type=EntityType.PROCESS_NAME, subject_value="powershell.exe")
    pkg = generate(_summary([finding]))
    assert DetectionPackage.model_validate_json(pkg.model_dump_json()) == pkg


# --------------------------------------------------------------------------- #
# Golden snapshots (fixed IP finding)
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(("gen_cls", "name", "lang", "tokens"), _GENERATORS, ids=_IDS)
def test_golden_snapshot(gen_cls: Any, name: str, lang: str, tokens: tuple[str, ...]) -> None:
    finding = _finding(
        fid="fnd_0011223344556677",
        severity=Severity.CRITICAL,
        relationships=[_attack("T1071.001")],
    )
    summary = _summary([finding], generated_at=datetime(2024, 6, 1, tzinfo=UTC))
    # Note: the fixture confidence is VERY_HIGH/90 to match the captured golden.
    artifact = gen_cls().generate(summary)[0]
    expected_id, expected_sha = _GOLDEN[name]
    assert artifact.id == expected_id
    assert hashlib.sha256(artifact.content.encode()).hexdigest()[:16] == expected_sha


# --------------------------------------------------------------------------- #
# API contract
# --------------------------------------------------------------------------- #


_SIEM_LANGS = {"splunk_spl", "sentinel_kql", "elastic_esql", "chronicle_yara_l", "qradar_aql"}


class TestSiemAPI:
    client = TestClient(app)

    def _languages(self, finding: Finding) -> set[str]:
        body = _summary([finding]).model_dump(mode="json")
        res = self.client.post("/api/v1/detections", json=body)
        assert res.status_code == 200
        return set(res.json()["languages"])

    def test_process_finding_yields_all_siem_platforms(self) -> None:
        finding = _finding(subject_type=EntityType.PROCESS_NAME, subject_value="powershell.exe")
        assert self._languages(finding) >= _SIEM_LANGS

    def test_unsupported_finding_has_no_siem(self) -> None:
        finding = _finding(subject_type=EntityType.CWE, subject_value="CWE-79")
        assert not (_SIEM_LANGS & self._languages(finding))
