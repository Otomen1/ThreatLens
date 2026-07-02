"""YARA detection generator tests (Phase 4.2).

Covers registration alongside Sigma, file-hash mapping, rejection of everything
non-file (IPs/domains/URLs/CVE/CWE/CAPEC/actors/techniques/malware names/
informational/invalid hashes), deterministic + timestamp-independent identity,
duplicate suppression, traceability, serialization, a golden snapshot, and the
API contract. The generator consumes only Finding objects.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

from fastapi.testclient import TestClient

from threatlens.api.app import app
from threatlens.detection import (
    DetectionLanguage,
    DetectionPackage,
    DetectionSeverity,
    YaraGenerator,
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
_REQUIRED_META = (
    "description",
    "author",
    "date",
    "reference",
    "finding_ids",
    "rule_id",
    "detection_id",
    "source",
    "threatlens_version",
    "severity",
    "hash",
)


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
    subject_type: EntityType = EntityType.SHA256,
    subject_value: str = _SHA256,
    severity: Severity = Severity.HIGH,
    categories: frozenset[FindingCategory] = frozenset({FindingCategory.MALWARE}),
    sources: Sequence[str] = ("malwarebazaar",),
    relationships: Sequence[AttributedRelationship] = (),
) -> Finding:
    return Finding(
        id=fid,
        title="Example finding",
        categories=categories,
        subject_type=subject_type,
        subject_value=subject_value,
        severity=severity,
        confidence=Confidence(score=80, band=ConfidenceBand.HIGH),
        sources=list(sources),
        relationships=list(relationships),
    )


def _summary(findings: Sequence[Finding], *, generated_at: datetime = _NOW) -> InvestigationSummary:
    first = findings[0]
    return InvestigationSummary(
        entity_type=first.subject_type,
        entity_value=first.subject_value,
        posture=Severity.HIGH,
        overall_confidence=Confidence(score=80, band=ConfidenceBand.HIGH),
        findings=list(findings),
        engine_version="1.0",
        generated_at=generated_at,
    )


def _yara(findings: Sequence[Finding], *, generated_at: datetime = _NOW) -> list[Any]:
    return list(YaraGenerator().generate(_summary(findings, generated_at=generated_at)))


# --------------------------------------------------------------------------- #
# Registration
# --------------------------------------------------------------------------- #


def test_yara_registered_alongside_sigma() -> None:
    names = [g.name for g in build_default_registry().generators]
    assert "yara" in names and "sigma" in names


def test_engine_emits_yara_for_a_hash_finding() -> None:
    pkg = generate(_summary([_finding()]))
    assert DetectionLanguage.YARA in pkg.languages
    yara = [a for a in pkg.artifacts if a.language == DetectionLanguage.YARA]
    assert len(yara) == 1


# --------------------------------------------------------------------------- #
# Supported mappings (file hashes)
# --------------------------------------------------------------------------- #


def test_maps_each_hash_type() -> None:
    cases = {
        EntityType.MD5: ("d41d8cd98f00b204e9800998ecf8427e", "md5"),
        EntityType.SHA1: ("da39a3ee5e6b4b0d3255bfef95601890afd80709", "sha1"),
        EntityType.SHA256: (_SHA256, "sha256"),
    }
    for subject_type, (value, func) in cases.items():
        artifacts = _yara([_finding(subject_type=subject_type, subject_value=value)])
        assert len(artifacts) == 1, subject_type
        content = artifacts[0].content
        assert f'hash.{func}(0, filesize) == "{value}"' in content
        assert 'import "hash"' in content


# --------------------------------------------------------------------------- #
# Unsupported / invalid — no rule
# --------------------------------------------------------------------------- #


def test_non_file_subjects_yield_no_rule() -> None:
    for subject_type, value in [
        (EntityType.IPV4, "1.2.3.4"),
        (EntityType.IPV6, "2001:db8::1"),
        (EntityType.DOMAIN, "evil.example.net"),
        (EntityType.URL, "http://evil.example.net/x"),
        (EntityType.CVE, "CVE-2021-44228"),
        (EntityType.CWE, "CWE-79"),
        (EntityType.CAPEC, "CAPEC-66"),
        (EntityType.THREAT_ACTOR, "APT28"),
        (EntityType.MITRE_TECHNIQUE, "T1059"),
        (EntityType.MALWARE_FAMILY, "emotet"),
    ]:
        assert _yara([_finding(subject_type=subject_type, subject_value=value)]) == []


def test_informational_and_invalid_hashes_are_skipped() -> None:
    assert _yara([_finding(severity=Severity.INFORMATIONAL)]) == []
    assert _yara([_finding(subject_value="not-a-hash")]) == []
    assert _yara([_finding(subject_type=EntityType.MD5, subject_value="abc")]) == []  # wrong length


def test_rules_never_contain_network_iocs() -> None:
    content = _yara([_finding()])[0].content
    for forbidden in ("dst_ip", "http://", "1.2.3.4", "logsource"):
        assert forbidden not in content


# --------------------------------------------------------------------------- #
# Structure & traceability
# --------------------------------------------------------------------------- #


def test_rule_structure_and_meta() -> None:
    artifact = _yara([_finding(relationships=[_attack("T1204")])])[0]
    content = artifact.content
    assert content.startswith('import "hash"')
    assert content.count("rule ThreatLens_Malware_") == 1
    assert "meta:" in content and "condition:" in content
    for key in _REQUIRED_META:
        assert f"{key} = " in content, key
    assert "mitre_attack = " in content  # technique present


def test_traceability_metadata() -> None:
    finding = _finding(fid="fnd_trace", relationships=[_attack("T1204")])
    artifact = _yara([finding])[0]
    assert artifact.metadata["finding_ids"] == "fnd_trace"
    assert artifact.metadata["rule_id"] == artifact.rule_id
    assert artifact.metadata["detection_id"] == artifact.id
    assert artifact.metadata["source"] == "Generated from InvestigationSummary"
    assert any("fnd_trace" in r.title for r in artifact.references)
    assert any(r.url and "attack.mitre.org" in r.url for r in artifact.references)


# --------------------------------------------------------------------------- #
# Determinism / stable ids / dedup
# --------------------------------------------------------------------------- #


def test_generation_is_deterministic() -> None:
    findings = [_finding()]
    assert _yara(findings) == _yara(findings)


def test_ids_are_timestamp_independent() -> None:
    early = generate(_summary([_finding()], generated_at=datetime(2024, 1, 1, tzinfo=UTC)))
    late = generate(_summary([_finding()], generated_at=datetime(2025, 9, 9, tzinfo=UTC)))
    ye = next(a for a in early.artifacts if a.language == DetectionLanguage.YARA)
    yl = next(a for a in late.artifacts if a.language == DetectionLanguage.YARA)
    assert ye.id == yl.id
    assert ye.rule_id == yl.rule_id
    assert early.id == late.id
    assert 'date = "2024-01-01"' in ye.content
    assert 'date = "2025-09-09"' in yl.content


def test_same_hash_same_rule_id() -> None:
    a = _yara([_finding(fid="fnd_x")])[0]
    b = _yara([_finding(fid="fnd_y")])[0]
    assert a.rule_id == b.rule_id


def test_duplicate_findings_on_same_hash_are_merged() -> None:
    findings = [
        _finding(fid="fnd_a", severity=Severity.MEDIUM),
        _finding(fid="fnd_b", severity=Severity.CRITICAL),
    ]
    artifacts = _yara(findings)
    assert len(artifacts) == 1
    assert artifacts[0].metadata["finding_ids"] == "fnd_a,fnd_b"
    assert artifacts[0].severity == DetectionSeverity.CRITICAL


# --------------------------------------------------------------------------- #
# Serialization
# --------------------------------------------------------------------------- #


def test_package_round_trips_through_json() -> None:
    pkg = generate(_summary([_finding(relationships=[_attack("T1204")])]))
    assert DetectionPackage.model_validate_json(pkg.model_dump_json()) == pkg


# --------------------------------------------------------------------------- #
# Golden snapshot
# --------------------------------------------------------------------------- #

_GOLDEN_DESCRIPTION = (
    '        description = "Detects a file matching a hash flagged as malicious '
    'by ThreatLens finding(s) fnd_0011223344556677 via malwarebazaar."'
)
_GOLDEN_CONDITION = f'        filesize < 100MB and hash.sha256(0, filesize) == "{_SHA256}"'
_GOLDEN_YARA = (
    "\n".join(
        [
            'import "hash"',
            "",
            "rule ThreatLens_Malware_0364e78be895",
            "{",
            "    meta:",
            _GOLDEN_DESCRIPTION,
            '        author = "ThreatLens Detection Engine"',
            '        date = "2024-06-01"',
            '        reference = "https://attack.mitre.org/techniques/T1204/002/"',
            '        finding_ids = "fnd_0011223344556677"',
            '        rule_id = "yar_0364e78be895cef9"',
            '        detection_id = "det_a4181fdfe089b0cb"',
            '        source = "Generated from InvestigationSummary"',
            '        threatlens_version = "1.0.0"',
            '        severity = "critical"',
            '        hash_type = "sha256"',
            f'        hash = "{_SHA256}"',
            '        mitre_attack = "T1204.002"',
            "    condition:",
            _GOLDEN_CONDITION,
            "}",
        ]
    )
    + "\n"
)


def test_golden_snapshot() -> None:
    finding = _finding(
        fid="fnd_0011223344556677",
        severity=Severity.CRITICAL,
        relationships=[_attack("T1204.002")],
    )
    artifact = _yara([finding], generated_at=datetime(2024, 6, 1, tzinfo=UTC))[0]
    assert artifact.content == _GOLDEN_YARA
    assert artifact.id == "det_a4181fdfe089b0cb"


# --------------------------------------------------------------------------- #
# API contract
# --------------------------------------------------------------------------- #


class TestYaraAPI:
    client = TestClient(app)

    def test_package_contains_sigma_and_yara_for_a_hash(self) -> None:
        summary = _summary([_finding(relationships=[_attack("T1204")])])
        res = self.client.post("/api/v1/detections", json=summary.model_dump(mode="json"))
        assert res.status_code == 200
        pkg = res.json()
        assert set(pkg["languages"]) == {"sigma", "yara"}
        yara = [a for a in pkg["artifacts"] if a["language"] == "yara"]
        assert len(yara) == 1
        assert yara[0]["content"].startswith('import "hash"')
        assert yara[0]["metadata"]["finding_ids"] == "fnd_1"

    def test_no_yara_for_non_file_finding(self) -> None:
        summary = _summary([_finding(subject_type=EntityType.DOMAIN, subject_value="evil.net")])
        res = self.client.post("/api/v1/detections", json=summary.model_dump(mode="json"))
        yara = [a for a in res.json()["artifacts"] if a["language"] == "yara"]
        assert yara == []
