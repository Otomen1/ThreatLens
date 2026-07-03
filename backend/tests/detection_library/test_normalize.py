"""Normalization tests: raw record → CommunityRule (deterministic, offline)."""

from __future__ import annotations

from threatlens.detection_library import RuleLicense, RuleSource, normalize_record
from threatlens.detection_library.normalize import (
    community_rule_id,
    content_fingerprint,
    extract_iocs,
    extract_mitre,
    infer_category,
    infer_platforms,
    infer_severity,
)
from threatlens.detection_library.types import (
    DetectionCategory,
    DetectionLanguage,
    DetectionSeverity,
    LicenseSupport,
    RulePlatform,
)
from threatlens.entities.types import EntityType

_PERMISSIVE = RuleLicense(spdx_id="MIT", name="MIT", support=LicenseSupport.PERMISSIVE)
_RESTRICTED = RuleLicense(spdx_id="Elastic-2.0", name="Elastic", support=LicenseSupport.RESTRICTED)

_SIGMA_SOURCE = RuleSource(
    id="src",
    name="Src",
    repository="o/r",
    url="https://example.test/o/r",
    license=_PERMISSIVE,
    languages=(DetectionLanguage.SIGMA,),
)


def _record(**over: object) -> dict[str, object]:
    base: dict[str, object] = {
        "rule_id": "r1",
        "name": "Rule One",
        "author": "Alice",
        "content": "title: t\nlevel: high\nlogsource:\n    product: windows\n    "
        "category: process_creation\ntags:\n    - attack.t1059.001\n",
    }
    base.update(over)
    return base


# --------------------------------------------------------------------------- #
# Extraction primitives
# --------------------------------------------------------------------------- #


def test_extract_mitre_normalizes_and_sorts() -> None:
    assert extract_mitre("attack.t1059.001 and T1071 plus t1204") == ("T1059.001", "T1071", "T1204")


def test_extract_mitre_empty_when_absent() -> None:
    assert extract_mitre("no techniques here") == ()


def test_extract_iocs_recognizes_ip_hash_domain() -> None:
    content = (
        "dest 45.155.205.233 sha256 "
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f "
        "domain malware-c2.example.net"
    )
    kinds = {(i.type, i.value) for i in extract_iocs(content)}
    assert (EntityType.IPV4, "45.155.205.233") in kinds
    assert (EntityType.DOMAIN, "malware-c2.example.net") in kinds
    assert any(i.type is EntityType.SHA256 for i in extract_iocs(content))


def test_extract_iocs_rejects_field_names_and_reference_hosts() -> None:
    # Elastic/KQL field tokens and vendor reference domains must not be IOCs.
    content = "process.name host.name event.type see https://github.com/x attack.mitre.org/y"
    assert extract_iocs(content) == ()


def test_extract_iocs_rejects_invalid_ipv4() -> None:
    assert not any(i.type is EntityType.IPV4 for i in extract_iocs("999.999.1.1 is not an ip"))


def test_infer_severity_from_sigma_level() -> None:
    assert infer_severity("level: critical\n", None) is DetectionSeverity.CRITICAL
    assert infer_severity("no level", "low") is DetectionSeverity.LOW
    assert infer_severity("no level", None) is DetectionSeverity.MEDIUM


def test_infer_category_and_platforms() -> None:
    assert infer_category(DetectionLanguage.SURICATA, "") is DetectionCategory.NETWORK
    assert infer_category(DetectionLanguage.YARA, "") is DetectionCategory.FILE
    assert infer_category(DetectionLanguage.SIGMA, "category: dns_query") is DetectionCategory.DNS
    assert RulePlatform.NETWORK in infer_platforms(DetectionLanguage.SNORT, "", [])
    assert RulePlatform.WINDOWS in infer_platforms(DetectionLanguage.SIGMA, "product: windows", [])


# --------------------------------------------------------------------------- #
# Identity + versioning
# --------------------------------------------------------------------------- #


def test_rule_id_is_content_addressed_and_stable() -> None:
    fp = content_fingerprint("body")
    assert community_rule_id("src", "r1", fp) == community_rule_id("SRC", "R1", fp)
    assert community_rule_id("src", "r1", fp).startswith("com_")


def test_fingerprint_changes_with_content() -> None:
    assert content_fingerprint("a") != content_fingerprint("b")


# --------------------------------------------------------------------------- #
# End-to-end normalize_record
# --------------------------------------------------------------------------- #


def test_normalize_record_is_deterministic() -> None:
    assert normalize_record(_SIGMA_SOURCE, _record()) == normalize_record(_SIGMA_SOURCE, _record())


def test_normalize_record_populates_the_canonical_model() -> None:
    rule = normalize_record(_SIGMA_SOURCE, _record())
    assert rule.language is DetectionLanguage.SIGMA
    assert rule.category is DetectionCategory.PROCESS
    assert rule.severity is DetectionSeverity.HIGH
    assert rule.mitre_techniques == ("T1059.001",)
    assert RulePlatform.WINDOWS in rule.platforms
    assert rule.author.name == "Alice"
    assert rule.content is not None  # permissive → body preserved verbatim
    assert rule.content.rstrip().endswith("attack.t1059.001")


def test_language_falls_back_to_source_default() -> None:
    rule = normalize_record(_SIGMA_SOURCE, _record(language="not-a-language"))
    assert rule.language is DetectionLanguage.SIGMA


def test_restricted_license_withholds_content_but_keeps_metadata() -> None:
    source = _SIGMA_SOURCE.model_copy(update={"license": _RESTRICTED})
    rule = normalize_record(source, _record())
    assert rule.content is None  # body withheld
    assert rule.license.support is LicenseSupport.RESTRICTED
    assert rule.mitre_techniques == ("T1059.001",)  # signals still extracted
    assert rule.author.name == "Alice"  # attribution preserved
