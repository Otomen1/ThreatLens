"""Sigma detection generator tests (Phase 4.1).

Exhaustive coverage of the first concrete generator: registry execution, finding
mapping, unsupported/informational filtering, deterministic YAML generation
(validated as real YAML), duplicate suppression, timestamp-independent stable
ids, traceability, serialization, a golden snapshot, and the API contract. The
Reasoning Engine is never exercised for generation — the generator consumes only
Finding objects.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

import yaml
from fastapi.testclient import TestClient

from threatlens.api.app import app
from threatlens.detection import (
    DetectionLanguage,
    DetectionPackage,
    DetectionSeverity,
    SigmaGenerator,
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
_REQUIRED_SIGMA_KEYS = {
    "title",
    "id",
    "status",
    "description",
    "author",
    "references",
    "date",
    "logsource",
    "detection",
    "falsepositives",
    "level",
    "tags",
}


def _attack(technique: str) -> AttributedRelationship:
    return AttributedRelationship(
        relationship=Relationship(
            relationship=RelationshipType.ASSOCIATED_WITH,
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
        confidence=Confidence(score=70, band=ConfidenceBand.HIGH),
        sources=list(sources),
        relationships=list(relationships),
    )


def _summary(findings: Sequence[Finding], *, generated_at: datetime = _NOW) -> InvestigationSummary:
    first = findings[0]
    return InvestigationSummary(
        entity_type=first.subject_type,
        entity_value=first.subject_value,
        posture=Severity.HIGH,
        overall_confidence=Confidence(score=70, band=ConfidenceBand.HIGH),
        findings=list(findings),
        engine_version="1.0",
        generated_at=generated_at,
    )


def _sigma(findings: Sequence[Finding], *, generated_at: datetime = _NOW) -> list[Any]:
    return list(SigmaGenerator().generate(_summary(findings, generated_at=generated_at)))


# --------------------------------------------------------------------------- #
# Registry execution
# --------------------------------------------------------------------------- #


def test_sigma_is_registered_by_default() -> None:
    registry = build_default_registry()
    assert registry.get("sigma") is not None
    assert DetectionLanguage.SIGMA in registry.languages


def test_engine_runs_sigma_via_default_registry() -> None:
    pkg = generate(_summary([_finding()]))
    assert not pkg.is_empty
    assert DetectionLanguage.SIGMA in pkg.languages
    assert any(a.language == DetectionLanguage.SIGMA for a in pkg.artifacts)


# --------------------------------------------------------------------------- #
# Finding mapping (supported IOC subject types)
# --------------------------------------------------------------------------- #


def test_maps_each_supported_ioc_subject() -> None:
    cases = {
        EntityType.IPV4: ("1.2.3.4", "firewall", "dst_ip"),
        EntityType.IPV6: ("2001:db8::1", "firewall", "dst_ip"),
        EntityType.DOMAIN: ("evil.example.net", "dns", "query"),
        EntityType.URL: ("http://evil.example.net/x", "proxy", "c-uri|contains"),
        EntityType.MD5: ("d41d8cd98f00b204e9800998ecf8427e", "process_creation", "Hashes|contains"),
        EntityType.SHA1: ("a" * 40, "process_creation", "Hashes|contains"),
        EntityType.SHA256: ("b" * 64, "process_creation", "Hashes|contains"),
    }
    for subject_type, (value, category, field) in cases.items():
        artifacts = _sigma([_finding(subject_type=subject_type, subject_value=value)])
        assert len(artifacts) == 1, subject_type
        doc = yaml.safe_load(artifacts[0].content)
        assert doc["logsource"]["category"] == category
        assert field in doc["detection"]["selection"]
        assert doc["detection"]["selection"][field] == value


def test_unsupported_subjects_yield_no_rule() -> None:
    for subject_type, value in [
        (EntityType.CWE, "CWE-79"),
        (EntityType.CAPEC, "CAPEC-66"),
        (EntityType.CVE, "CVE-2021-44228"),
        (EntityType.MITRE_TECHNIQUE, "T1059"),
        (EntityType.MALWARE_FAMILY, "emotet"),
        (EntityType.THREAT_ACTOR, "APT28"),
    ]:
        assert _sigma([_finding(subject_type=subject_type, subject_value=value)]) == []


def test_informational_findings_are_skipped() -> None:
    assert _sigma([_finding(severity=Severity.INFORMATIONAL)]) == []
    assert (
        _sigma(
            [_finding(severity=Severity.LOW, categories=frozenset({FindingCategory.INFORMATIONAL}))]
        )
        == []
    )


# --------------------------------------------------------------------------- #
# YAML generation (valid, complete)
# --------------------------------------------------------------------------- #


def test_yaml_is_valid_and_complete() -> None:
    artifact = _sigma([_finding()])[0]
    doc = yaml.safe_load(artifact.content)
    assert set(doc) >= _REQUIRED_SIGMA_KEYS
    assert doc["status"] == "experimental"
    assert doc["author"] == "ThreatLens Detection Engine"
    assert doc["detection"]["condition"] == "selection"
    assert doc["level"] in {"informational", "low", "medium", "high", "critical"}
    assert uuid.UUID(doc["id"])  # a valid UUID


def test_level_tracks_max_severity() -> None:
    levels = {}
    for severity in (Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL):
        doc = yaml.safe_load(_sigma([_finding(severity=severity)])[0].content)
        levels[severity] = doc["level"]
    assert levels == {
        Severity.LOW: "low",
        Severity.MEDIUM: "medium",
        Severity.HIGH: "high",
        Severity.CRITICAL: "critical",
    }


# --------------------------------------------------------------------------- #
# Traceability
# --------------------------------------------------------------------------- #


def test_traceability_finding_ids_subject_and_attack() -> None:
    finding = _finding(fid="fnd_trace", relationships=[_attack("T1071")])
    artifact = _sigma([finding])[0]
    doc = yaml.safe_load(artifact.content)

    # finding_ids required inside metadata
    assert artifact.metadata["finding_ids"] == "fnd_trace"
    assert artifact.metadata["subject"] == finding.subject_value
    # cited in the rule: finding id, subject, and MITRE ATT&CK
    assert any("fnd_trace" in ref for ref in doc["references"])
    assert finding.subject_value in doc["description"]
    assert "attack.t1071" in doc["tags"]
    assert any("attack.mitre.org/techniques/T1071" in ref for ref in doc["references"])


def test_no_attack_tag_without_relationship() -> None:
    doc = yaml.safe_load(_sigma([_finding()])[0].content)
    assert not any(tag.startswith("attack.") for tag in doc["tags"])
    assert doc["tags"] == ["threatlens.detection"]


# --------------------------------------------------------------------------- #
# Determinism, stable ids, duplicate suppression
# --------------------------------------------------------------------------- #


def test_generation_is_deterministic() -> None:
    findings = [_finding(fid="fnd_a"), _finding(fid="fnd_b", subject_value="9.9.9.9")]
    assert _sigma(findings) == _sigma(findings)


def test_ids_are_timestamp_independent() -> None:
    early = generate(_summary([_finding()], generated_at=datetime(2024, 1, 1, tzinfo=UTC)))
    late = generate(_summary([_finding()], generated_at=datetime(2025, 9, 9, tzinfo=UTC)))
    assert early.artifacts[0].id == late.artifacts[0].id  # framework id stable
    assert early.artifacts[0].rule_id == late.artifacts[0].rule_id  # Sigma UUID stable
    assert early.id == late.id  # package id stable
    # ...but the human-readable date reflects the investigation.
    assert "2024-01-01" in early.artifacts[0].content
    assert "2025-09-09" in late.artifacts[0].content


def test_same_ioc_yields_same_uuid_across_investigations() -> None:
    a = _sigma([_finding(fid="fnd_x")])[0]
    b = _sigma([_finding(fid="fnd_y")])[0]  # different finding, same IOC
    assert a.rule_id == b.rule_id


def test_duplicate_findings_on_same_ioc_are_merged() -> None:
    findings = [
        _finding(fid="fnd_a", severity=Severity.MEDIUM),
        _finding(fid="fnd_b", severity=Severity.CRITICAL),
    ]
    artifacts = _sigma(findings)
    assert len(artifacts) == 1  # one rule per IOC
    assert artifacts[0].metadata["finding_ids"] == "fnd_a,fnd_b"
    assert artifacts[0].severity == DetectionSeverity.CRITICAL  # max severity
    assert set(artifacts[0].source_finding_ids) == {"fnd_a", "fnd_b"}


def test_distinct_iocs_yield_distinct_rules() -> None:
    artifacts = _sigma(
        [_finding(fid="a", subject_value="1.1.1.1"), _finding(fid="b", subject_value="2.2.2.2")]
    )
    assert len(artifacts) == 2
    assert len({a.id for a in artifacts}) == 2
    assert len({a.rule_id for a in artifacts}) == 2


# --------------------------------------------------------------------------- #
# Serialization
# --------------------------------------------------------------------------- #


def test_package_round_trips_through_json() -> None:
    pkg = generate(_summary([_finding(relationships=[_attack("T1071")])]))
    assert DetectionPackage.model_validate_json(pkg.model_dump_json()) == pkg


# --------------------------------------------------------------------------- #
# Golden snapshot (locks the exact YAML format)
# --------------------------------------------------------------------------- #

# Built line-by-line (rather than one triple-quoted block) only so the long
# description line stays under the lint limit; the runtime value is exact YAML.
_GOLDEN_DESCRIPTION = (
    "description: 'Detects network connections to 45.155.205.233, flagged as "
    "malicious by ThreatLens finding(s) fnd_0011223344556677 via abuseipdb.'"
)
_GOLDEN_YAML = (
    "\n".join(
        [
            "title: 'Malicious IP address: 45.155.205.233'",
            "id: 646fb072-055e-57f5-884e-dc3d85885caf",
            "status: experimental",
            _GOLDEN_DESCRIPTION,
            "author: 'ThreatLens Detection Engine'",
            "references:",
            "    - 'https://attack.mitre.org/techniques/T1071/001/'",
            "    - 'ThreatLens finding: fnd_0011223344556677'",
            "date: 2024-06-01",
            "tags:",
            "    - threatlens.detection",
            "    - attack.t1071.001",
            "logsource:",
            "    category: firewall",
            "detection:",
            "    selection:",
            "        dst_ip: '45.155.205.233'",
            "    condition: selection",
            "falsepositives:",
            "    - 'Legitimate traffic to this destination'",
            "level: critical",
        ]
    )
    + "\n"
)


def test_golden_snapshot() -> None:
    finding = _finding(
        fid="fnd_0011223344556677",
        severity=Severity.CRITICAL,
        relationships=[_attack("T1071.001")],
    )
    pkg = generate(_summary([finding], generated_at=datetime(2024, 6, 1, tzinfo=UTC)))
    artifact = next(a for a in pkg.artifacts if a.language is DetectionLanguage.SIGMA)
    assert artifact.content == _GOLDEN_YAML
    assert artifact.id == "det_07b06b9432c4a655"
    assert yaml.safe_load(artifact.content)  # still valid YAML


# --------------------------------------------------------------------------- #
# API contract
# --------------------------------------------------------------------------- #


class TestSigmaAPI:
    client = TestClient(app)

    def test_detections_endpoint_returns_sigma(self) -> None:
        summary = _summary([_finding(relationships=[_attack("T1071")])])
        res = self.client.post("/api/v1/detections", json=summary.model_dump(mode="json"))
        assert res.status_code == 200
        pkg = res.json()
        assert "sigma" in pkg["languages"]
        artifact = next(a for a in pkg["artifacts"] if a["language"] == "sigma")
        assert artifact["content"].startswith("title:")
        assert artifact["metadata"]["finding_ids"] == "fnd_1"

    def test_detections_endpoint_empty_for_unsupported(self) -> None:
        summary = _summary(
            [_finding(subject_type=EntityType.MITRE_TECHNIQUE, subject_value="T1059")]
        )
        res = self.client.post("/api/v1/detections", json=summary.model_dump(mode="json"))
        assert res.status_code == 200
        assert res.json()["artifacts"] == []
