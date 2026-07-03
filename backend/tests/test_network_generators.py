"""Suricata & Snort network detection generator tests (Phase 4.3).

Covers registration, per-kind mappings (IP/domain/URL), rejection of every
non-network subject, structure + traceability, determinism, deterministic stable
SIDs/ids, duplicate suppression, serialization, golden snapshots, and the API
contract. Both generators consume only Finding objects.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

import pytest
from fastapi.testclient import TestClient

from threatlens.api.app import app
from threatlens.detection import (
    DetectionLanguage,
    DetectionPackage,
    DetectionSeverity,
    SnortGenerator,
    SuricataGenerator,
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
_ENGINES = (SuricataGenerator, SnortGenerator)
_REQUIRED_OPTIONS = ("msg:", "sid:", "rev:", "classtype:", "metadata:", "reference:", "priority:")


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


def _rules(gen: Any, findings: Sequence[Finding]) -> list[Any]:
    return list(gen.generate(_summary(findings)))


def _one(gen: Any, subject_type: EntityType, value: str) -> str:
    finding = _finding(subject_type=subject_type, subject_value=value)
    return _rules(gen, [finding])[0].content


# --------------------------------------------------------------------------- #
# Registration
# --------------------------------------------------------------------------- #


def test_both_engines_registered() -> None:
    names = [g.name for g in build_default_registry().generators]
    assert "suricata" in names and "snort" in names


def test_package_carries_network_rules_for_an_ip() -> None:
    pkg = generate(_summary([_finding()]))
    langs = set(pkg.languages)
    assert {DetectionLanguage.SURICATA, DetectionLanguage.SNORT} <= langs


# --------------------------------------------------------------------------- #
# Supported mappings
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("gen_cls", _ENGINES)
def test_ip_rule_shape(gen_cls: Any) -> None:
    rule = _rules(gen_cls(), [_finding()])[0].content
    assert rule.startswith("alert ip $HOME_NET any -> 45.155.205.233 any (")
    for opt in _REQUIRED_OPTIONS:
        assert opt in rule


def test_domain_mapping_per_engine() -> None:
    suri = _one(SuricataGenerator(), EntityType.DOMAIN, "evil.net")
    snort = _one(SnortGenerator(), EntityType.DOMAIN, "evil.net")
    assert "alert dns" in suri and "dns.query" in suri and 'content:"evil.net"' in suri
    assert "$HTTP_PORTS" in snort and "http_header" in snort


def test_url_mapping_encodes_query_bytes() -> None:
    suri = _one(SuricataGenerator(), EntityType.URL, "http://evil.net/gate.php?id=1")
    assert "http.host" in suri and "http.uri" in suri
    assert 'content:"evil.net"' in suri
    assert "|3F|" in suri and "|3D|" in suri  # ? and = hex-encoded


# --------------------------------------------------------------------------- #
# Unsupported — no rule
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("gen_cls", _ENGINES)
def test_non_network_subjects_yield_no_rule(gen_cls: Any) -> None:
    for subject_type, value in [
        (EntityType.MD5, "d41d8cd98f00b204e9800998ecf8427e"),
        (EntityType.SHA256, "a" * 64),
        (EntityType.CVE, "CVE-2021-44228"),
        (EntityType.CWE, "CWE-79"),
        (EntityType.CAPEC, "CAPEC-66"),
        (EntityType.THREAT_ACTOR, "APT28"),
        (EntityType.MITRE_TECHNIQUE, "T1059"),
    ]:
        assert _rules(gen_cls(), [_finding(subject_type=subject_type, subject_value=value)]) == []


@pytest.mark.parametrize("gen_cls", _ENGINES)
def test_informational_findings_skipped(gen_cls: Any) -> None:
    assert _rules(gen_cls(), [_finding(severity=Severity.INFORMATIONAL)]) == []


# --------------------------------------------------------------------------- #
# Traceability
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("gen_cls", _ENGINES)
def test_traceability(gen_cls: Any) -> None:
    artifact = _rules(gen_cls(), [_finding(fid="fnd_trace", relationships=[_attack("T1071")])])[0]
    content = artifact.content
    assert "finding_id fnd_trace" in content
    assert f"rule_id {artifact.rule_id}" in content
    assert f"detection_id {artifact.id}" in content
    assert "threatlens_version 1.0.0" in content
    assert "created_from investigation_summary" in content
    assert artifact.metadata["finding_ids"] == "fnd_trace"
    assert artifact.metadata["sid"].isdigit()


# --------------------------------------------------------------------------- #
# Determinism / stable ids / dedup
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("gen_cls", _ENGINES)
def test_deterministic_and_timestamp_independent(gen_cls: Any) -> None:
    gen = gen_cls()
    a = list(gen.generate(_summary([_finding()], generated_at=datetime(2024, 1, 1, tzinfo=UTC))))
    b = list(gen.generate(_summary([_finding()], generated_at=datetime(2025, 9, 9, tzinfo=UTC))))
    assert a == b  # network rules carry no date → fully identical


def test_sid_and_rule_id_stable_and_engine_distinct() -> None:
    suri = _rules(SuricataGenerator(), [_finding(fid="a")])[0]
    suri2 = _rules(SuricataGenerator(), [_finding(fid="b")])[0]  # same IOC, other finding
    snort = _rules(SnortGenerator(), [_finding(fid="a")])[0]
    assert suri.metadata["sid"] == suri2.metadata["sid"]  # stable per IOC
    assert suri.rule_id == suri2.rule_id
    assert suri.metadata["sid"] != snort.metadata["sid"]  # distinct per engine
    sid = int(suri.metadata["sid"])
    assert 1_000_000 <= sid < 10_000_000  # documented custom SID range


@pytest.mark.parametrize("gen_cls", _ENGINES)
def test_duplicate_findings_on_same_ioc_merge(gen_cls: Any) -> None:
    findings = [
        _finding(fid="fnd_a", severity=Severity.LOW),
        _finding(fid="fnd_b", severity=Severity.CRITICAL),
    ]
    artifacts = _rules(gen_cls(), findings)
    assert len(artifacts) == 1
    assert artifacts[0].metadata["finding_ids"] == "fnd_a,fnd_b"
    assert artifacts[0].severity == DetectionSeverity.CRITICAL
    assert "priority:1" in artifacts[0].content  # critical → priority 1


# --------------------------------------------------------------------------- #
# Serialization
# --------------------------------------------------------------------------- #


def test_package_round_trips_through_json() -> None:
    pkg = generate(_summary([_finding(relationships=[_attack("T1071")])]))
    assert DetectionPackage.model_validate_json(pkg.model_dump_json()) == pkg


# --------------------------------------------------------------------------- #
# Golden snapshots (IP rules, fixed input)
# --------------------------------------------------------------------------- #

_META_SUR = (
    "metadata:threatlens_version 1.0.0, rule_id sur_d534f5ac489b55a9, "
    "detection_id det_2e2399ac99b84db0, created_from investigation_summary, "
    "finding_id fnd_0011223344556677, source abuseipdb, mitre_attack T1071.001"
)
_META_SNR = (
    "metadata:threatlens_version 1.0.0, rule_id snr_bde4eff68898ee05, "
    "detection_id det_09ff43eb66568d66, created_from investigation_summary, "
    "finding_id fnd_0011223344556677, source abuseipdb, mitre_attack T1071.001"
)


def _golden(meta: str, sid: str) -> str:
    return (
        "alert ip $HOME_NET any -> 45.155.205.233 any ("
        + "; ".join(
            [
                'msg:"ThreatLens: Malicious IP address 45.155.205.233"',
                "classtype:trojan-activity",
                "reference:url,attack.mitre.org/techniques/T1071/001/",
                "reference:url,github.com/Otomen1/ThreatLens",
                meta,
                "priority:1",
                f"sid:{sid}",
                "rev:1",
            ]
        )
        + ";)\n"
    )


def _golden_finding() -> Finding:
    return _finding(
        fid="fnd_0011223344556677",
        severity=Severity.CRITICAL,
        relationships=[_attack("T1071.001")],
    )


def test_golden_suricata_ip() -> None:
    artifact = _rules(SuricataGenerator(), [_golden_finding()])[0]
    assert artifact.content == _golden(_META_SUR, "5724379")
    assert artifact.id == "det_2e2399ac99b84db0"


def test_golden_snort_ip() -> None:
    artifact = _rules(SnortGenerator(), [_golden_finding()])[0]
    assert artifact.content == _golden(_META_SNR, "4104600")
    assert artifact.id == "det_09ff43eb66568d66"


# --------------------------------------------------------------------------- #
# API contract
# --------------------------------------------------------------------------- #


class TestNetworkAPI:
    client = TestClient(app)

    def test_ip_yields_suricata_and_snort(self) -> None:
        summary = _summary([_finding(relationships=[_attack("T1071")])])
        res = self.client.post("/api/v1/detections", json=summary.model_dump(mode="json"))
        assert res.status_code == 200
        langs = set(res.json()["languages"])
        assert {"suricata", "snort"} <= langs

    def test_hash_finding_has_no_network_rules(self) -> None:
        summary = _summary([_finding(subject_type=EntityType.SHA256, subject_value="a" * 64)])
        res = self.client.post("/api/v1/detections", json=summary.model_dump(mode="json"))
        langs = set(res.json()["languages"])
        assert "suricata" not in langs and "snort" not in langs
