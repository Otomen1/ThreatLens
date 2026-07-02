"""The persisted IOC corpus — ~100 curated investigations (Phase 3.16).

Each :class:`IocCase` carries the raw query an analyst would type, the expected
detection outcome, and (for cases that exercise reasoning) provider-faithful
intelligence used to drive the engine offline. External TI provider results
(AbuseIPDB / OTX / URLhaus / MalwareBazaar) require network + keys, so they are
simulated with the exact ``EvidenceType`` / ``RelationshipTargetType`` /
``ReputationLevel`` values those providers normalize to; knowledge results
(NVD / MITRE / CWE / CAPEC) are simulated the same way. The result is a complete,
reproducible, offline regression dataset.

Detection, normalization, and routing are still validated against the *live*
engine in the harness — only the network-bound provider payloads are simulated.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from threatlens.entities.types import EntityType
from threatlens.providers.aggregation import (
    AggregatedResult,
    AttributedEvidence,
    AttributedRelationship,
    ProviderSummary,
)
from threatlens.providers.results import (
    Evidence,
    EvidenceType,
    Relationship,
    RelationshipTargetType,
    RelationshipType,
    Reputation,
    ReputationLevel,
    ResultStatus,
)
from threatlens.reasoning import ConfidenceBand, FindingCategory, Severity

NOW = datetime(2025, 1, 1, tzinfo=UTC)
RECENT = NOW - timedelta(days=5)
STALE = NOW - timedelta(days=400)

ET = EntityType
S = Severity
FC = FindingCategory
B = ConfidenceBand
RL = ReputationLevel
EVT = EvidenceType
RT = RelationshipType
RTT = RelationshipTargetType


# --------------------------------------------------------------------------- #
# Builders (provider-faithful)
# --------------------------------------------------------------------------- #


def _ev(
    evidence_type: EvidenceType,
    summary: str,
    *,
    value: str | None = None,
    sources: tuple[str, ...] = ("provider",),
    observed_at: datetime | None = None,
) -> AttributedEvidence:
    return AttributedEvidence(
        evidence=Evidence(
            type=evidence_type, summary=summary, value=value, observed_at=observed_at
        ),
        sources=list(sources),
    )


def _rel(
    relationship: RelationshipType,
    target_type: RelationshipTargetType,
    target_value: str,
    *,
    sources: tuple[str, ...] = ("provider",),
) -> AttributedRelationship:
    return AttributedRelationship(
        relationship=Relationship(
            relationship=relationship, target_type=target_type, target_value=target_value
        ),
        sources=list(sources),
    )


def _prov(
    provider: str,
    *,
    level: ReputationLevel | None = None,
    score: int | None = None,
    status: ResultStatus = ResultStatus.OK,
) -> ProviderSummary:
    reputation = Reputation(level=level, score=score) if level is not None else None
    return ProviderSummary(provider=provider, status=status, reputation=reputation)


def _agg(
    entity_type: EntityType,
    value: str,
    *,
    providers: tuple[ProviderSummary, ...] = (),
    evidence: tuple[AttributedEvidence, ...] = (),
    relationships: tuple[AttributedRelationship, ...] = (),
) -> AggregatedResult:
    return AggregatedResult(
        entity_type=entity_type,
        entity_value=value,
        providers=list(providers),
        evidence=list(evidence),
        relationships=list(relationships),
    )


def _empty(entity_type: EntityType, value: str) -> AggregatedResult:
    return AggregatedResult(entity_type=entity_type, entity_value=value)


# --------------------------------------------------------------------------- #
# Case model
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class IocCase:
    """One curated investigation and its expected pipeline outcome."""

    id: str
    category: str  # SOC-facing grouping (malicious_ip, phishing_domain, …)
    query: str
    expected_type: EntityType
    expected_normalized: str | None = None
    api_status: int = 200  # /detect HTTP status (422 = input correctly rejected)
    # Simulated intelligence (defaults to empty when omitted).
    ti: AggregatedResult | None = None
    knowledge: AggregatedResult | None = None
    # Reasoning expectations (checked when provided; the golden pins exact values).
    expect_findings: int | None = None
    expect_posture: Severity | None = None
    expect_categories: frozenset[FindingCategory] = frozenset()
    expect_min_recommendations: int | None = None
    expect_overall_band: ConfidenceBand | None = None


def _build() -> tuple[IocCase, ...]:  # noqa: C901 - a long, flat data table
    cases: list[IocCase] = []
    add = cases.append

    # ===================================================================== #
    # IP addresses
    # ===================================================================== #
    add(
        IocCase(
            "ip_malicious",
            "malicious_ip",
            "45.155.205.233",
            ET.IPV4,
            ti=_agg(
                ET.IPV4,
                "45.155.205.233",
                providers=(_prov("abuseipdb", level=RL.MALICIOUS, score=100),),
                evidence=(
                    _ev(
                        EVT.ABUSE_CONFIDENCE,
                        "Abuse confidence score: 100%",
                        value="100%",
                        sources=("abuseipdb",),
                        observed_at=RECENT,
                    ),
                ),
            ),
            expect_findings=1,
            expect_posture=S.HIGH,
            expect_categories=frozenset({FC.MALICIOUS_INFRASTRUCTURE}),
            expect_min_recommendations=2,
            expect_overall_band=B.HIGH,
        )
    )
    add(
        IocCase(
            "ip_malicious_corroborated",
            "malicious_ip",
            "194.5.249.10",
            ET.IPV4,
            ti=_agg(
                ET.IPV4,
                "194.5.249.10",
                providers=(
                    _prov("abuseipdb", level=RL.MALICIOUS, score=100),
                    _prov("otx", level=RL.SUSPICIOUS, score=60),
                ),
            ),
            expect_findings=1,
            expect_categories=frozenset({FC.MALICIOUS_INFRASTRUCTURE}),
        )
    )
    add(
        IocCase(
            "ip_suspicious",
            "suspicious_ip",
            "193.0.0.10",
            ET.IPV4,
            ti=_agg(
                ET.IPV4, "193.0.0.10", providers=(_prov("otx", level=RL.SUSPICIOUS, score=50),)
            ),
            expect_findings=1,
            expect_posture=S.HIGH,
        )
    )
    add(
        IocCase(
            "ip_likely_malicious",
            "suspicious_ip",
            "91.219.236.10",
            ET.IPV4,
            ti=_agg(
                ET.IPV4,
                "91.219.236.10",
                providers=(_prov("abuseipdb", level=RL.LIKELY_MALICIOUS, score=75),),
            ),
            expect_findings=1,
        )
    )
    add(
        IocCase(
            "ip_benign",
            "benign_ip",
            "8.8.8.8",
            ET.IPV4,
            ti=_agg(ET.IPV4, "8.8.8.8", providers=(_prov("abuseipdb", level=RL.BENIGN, score=0),)),
            expect_findings=0,
            expect_posture=S.INFORMATIONAL,
        )
    )
    add(
        IocCase(
            "ip_benign_cloudflare",
            "benign_ip",
            "1.1.1.1",
            ET.IPV4,
            ti=_agg(ET.IPV4, "1.1.1.1", providers=(_prov("abuseipdb", level=RL.BENIGN, score=0),)),
            expect_findings=0,
        )
    )
    add(
        IocCase(
            "ip_unknown",
            "unknown_ip",
            "203.0.113.55",
            ET.IPV4,
            ti=_agg(
                ET.IPV4,
                "203.0.113.55",
                providers=(
                    _prov("abuseipdb", status=ResultStatus.NOT_FOUND),
                    _prov("otx", status=ResultStatus.NOT_FOUND),
                ),
            ),
            expect_findings=0,
        )
    )
    add(
        IocCase(
            "ip_contested",
            "conflicting_ip",
            "5.45.207.10",
            ET.IPV4,
            ti=_agg(
                ET.IPV4,
                "5.45.207.10",
                providers=(
                    _prov("abuseipdb", level=RL.MALICIOUS, score=90),
                    _prov("otx", level=RL.BENIGN, score=0),
                ),
            ),
            expect_findings=1,
            expect_overall_band=B.MODERATE,
        )
    )
    add(
        IocCase(
            "ip_stale",
            "stale_ip",
            "212.83.40.10",
            ET.IPV4,
            ti=_agg(
                ET.IPV4,
                "212.83.40.10",
                providers=(_prov("otx"),),
                evidence=(
                    _ev(
                        EVT.DETECTION,
                        "Old C2 detection",
                        value="c2",
                        sources=("otx",),
                        observed_at=STALE,
                    ),
                ),
            ),
            expect_findings=1,
            expect_overall_band=B.MODERATE,
        )
    )
    add(
        IocCase(
            "ip_scanner_tag_only",
            "noise_ip",
            "198.51.100.7",
            ET.IPV4,
            ti=_agg(
                ET.IPV4,
                "198.51.100.7",
                providers=(_prov("otx"),),
                evidence=(_ev(EVT.TAG, "Tag: scanner", value="scanner", sources=("otx",)),),
            ),
            expect_findings=0,
        )
    )
    add(
        IocCase(
            "ip_c2_malware",
            "malicious_ip",
            "185.220.101.5",
            ET.IPV4,
            ti=_agg(
                ET.IPV4,
                "185.220.101.5",
                providers=(_prov("abuseipdb", level=RL.MALICIOUS, score=100),),
                relationships=(
                    _rel(RT.INDICATES, RTT.MALWARE_FAMILY, "Cobalt Strike", sources=("otx",)),
                ),
            ),
            expect_findings=2,
            expect_categories=frozenset({FC.MALICIOUS_INFRASTRUCTURE, FC.MALWARE}),
        )
    )
    add(
        IocCase(
            "ip_attributed_actor",
            "malicious_ip",
            "185.220.101.6",
            ET.IPV4,
            ti=_agg(
                ET.IPV4,
                "185.220.101.6",
                providers=(_prov("abuseipdb", level=RL.MALICIOUS, score=100),),
                relationships=(
                    _rel(RT.ATTRIBUTED_TO, RTT.THREAT_ACTOR, "APT29", sources=("otx",)),
                ),
            ),
            expect_findings=2,
            expect_categories=frozenset({FC.MALICIOUS_INFRASTRUCTURE, FC.THREAT_ACTOR}),
        )
    )
    add(
        IocCase(
            "ip_full_intel",
            "malicious_ip",
            "185.220.101.7",
            ET.IPV4,
            ti=_agg(
                ET.IPV4,
                "185.220.101.7",
                providers=(_prov("abuseipdb", level=RL.MALICIOUS, score=100),),
                relationships=(
                    _rel(RT.INDICATES, RTT.MALWARE_FAMILY, "Emotet", sources=("otx",)),
                    _rel(RT.ATTRIBUTED_TO, RTT.THREAT_ACTOR, "APT28", sources=("otx",)),
                    _rel(RT.USES, RTT.ATTACK_PATTERN, "T1071", sources=("otx",)),
                ),
            ),
            expect_findings=4,
            expect_categories=frozenset(
                {FC.MALICIOUS_INFRASTRUCTURE, FC.MALWARE, FC.THREAT_ACTOR, FC.ATTACK_PATTERN}
            ),
        )
    )
    add(
        IocCase(
            "ipv6_malicious",
            "malicious_ip",
            "2001:db8:dead::beef",
            ET.IPV6,
            ti=_agg(
                ET.IPV6,
                "2001:db8:dead::beef",
                providers=(_prov("abuseipdb", level=RL.MALICIOUS, score=100),),
            ),
            expect_findings=1,
            expect_categories=frozenset({FC.MALICIOUS_INFRASTRUCTURE}),
        )
    )
    add(
        IocCase(
            "ipv6_benign",
            "benign_ip",
            "2606:4700:4700::1111",
            ET.IPV6,
            ti=_agg(
                ET.IPV6,
                "2606:4700:4700::1111",
                providers=(_prov("abuseipdb", level=RL.BENIGN, score=0),),
            ),
            expect_findings=0,
        )
    )
    add(IocCase("ipv6_loopback", "benign_ip", "::1", ET.IPV6, expect_findings=0))
    add(IocCase("ip_private", "benign_ip", "10.0.0.1", ET.IPV4, expect_findings=0))

    # ===================================================================== #
    # Domains
    # ===================================================================== #
    add(
        IocCase(
            "domain_malware",
            "malware_domain",
            "malware-c2.net",
            ET.DOMAIN,
            ti=_agg(
                ET.DOMAIN,
                "malware-c2.net",
                providers=(_prov("urlhaus", level=RL.MALICIOUS, score=100),),
                evidence=(
                    _ev(
                        EVT.MALWARE_FAMILY,
                        "Malware family: Emotet",
                        value="Emotet",
                        sources=("urlhaus",),
                    ),
                ),
                relationships=(
                    _rel(RT.INDICATES, RTT.MALWARE_FAMILY, "Emotet", sources=("urlhaus",)),
                ),
            ),
            expect_findings=2,
            expect_categories=frozenset({FC.MALICIOUS_INFRASTRUCTURE, FC.MALWARE}),
        )
    )
    add(
        IocCase(
            "domain_phishing",
            "phishing_domain",
            "secure-login-update.net",
            ET.DOMAIN,
            ti=_agg(
                ET.DOMAIN,
                "secure-login-update.net",
                providers=(_prov("urlhaus", level=RL.MALICIOUS, score=100),),
                evidence=(
                    _ev(
                        EVT.CATEGORY,
                        "Threat type: phishing",
                        value="phishing",
                        sources=("urlhaus",),
                    ),
                ),
            ),
            expect_findings=1,
            expect_categories=frozenset({FC.MALICIOUS_INFRASTRUCTURE}),
        )
    )
    add(
        IocCase(
            "domain_typosquat",
            "typosquat_domain",
            "g00gle.com",
            ET.DOMAIN,
            ti=_agg(
                ET.DOMAIN, "g00gle.com", providers=(_prov("otx", level=RL.SUSPICIOUS, score=55),)
            ),
            expect_findings=1,
        )
    )
    add(
        IocCase(
            "domain_typosquat_paypal",
            "typosquat_domain",
            "paypa1-login.com",
            ET.DOMAIN,
            ti=_agg(
                ET.DOMAIN,
                "paypa1-login.com",
                providers=(_prov("otx", level=RL.SUSPICIOUS, score=50),),
            ),
            expect_findings=1,
        )
    )
    add(
        IocCase(
            "domain_legitimate",
            "benign_domain",
            "example.com",
            ET.DOMAIN,
            ti=_agg(ET.DOMAIN, "example.com", providers=(_prov("otx", level=RL.BENIGN, score=0),)),
            expect_findings=0,
        )
    )
    add(
        IocCase(
            "domain_newly_registered",
            "suspicious_domain",
            "kj3h4kjh23.net",
            ET.DOMAIN,
            ti=_agg(
                ET.DOMAIN,
                "kj3h4kjh23.net",
                providers=(_prov("otx", level=RL.SUSPICIOUS, score=45),),
            ),
            expect_findings=1,
        )
    )
    add(
        IocCase(
            "domain_parked",
            "benign_domain",
            "parked-domain.net",
            ET.DOMAIN,
            ti=_agg(
                ET.DOMAIN,
                "parked-domain.net",
                providers=(_prov("otx", status=ResultStatus.NOT_FOUND),),
            ),
            expect_findings=0,
        )
    )
    add(
        IocCase("domain_punycode", "idn_domain", "xn--80ak6aa92e.com", ET.DOMAIN, expect_findings=0)
    )
    add(
        IocCase(
            "domain_c2",
            "malware_domain",
            "update.bad-cdn.net",
            ET.DOMAIN,
            ti=_agg(
                ET.DOMAIN,
                "update.bad-cdn.net",
                providers=(_prov("otx", level=RL.SUSPICIOUS, score=60),),
                relationships=(
                    _rel(RT.INDICATES, RTT.MALWARE_FAMILY, "TrickBot", sources=("otx",)),
                    _rel(RT.USES, RTT.ATTACK_PATTERN, "T1071", sources=("otx",)),
                ),
            ),
            expect_findings=3,
        )
    )
    add(
        IocCase(
            "domain_attributed_benign_rep",
            "attribution_domain",
            "cdn.example.net",
            ET.DOMAIN,
            ti=_agg(
                ET.DOMAIN,
                "cdn.example.net",
                providers=(_prov("otx", level=RL.BENIGN, score=0),),
                relationships=(
                    _rel(RT.ATTRIBUTED_TO, RTT.THREAT_ACTOR, "APT29", sources=("otx",)),
                ),
            ),
            expect_findings=1,
            expect_categories=frozenset({FC.THREAT_ACTOR}),
        )
    )
    add(
        IocCase(
            "domain_unknown",
            "unknown_domain",
            "no-data-here.net",
            ET.DOMAIN,
            ti=_agg(
                ET.DOMAIN,
                "no-data-here.net",
                providers=(
                    _prov("urlhaus", status=ResultStatus.NOT_FOUND),
                    _prov("otx", status=ResultStatus.NOT_FOUND),
                ),
            ),
            expect_findings=0,
        )
    )
    add(
        IocCase(
            "domain_dga",
            "suspicious_domain",
            "a8f3kd9slxqz.net",
            ET.DOMAIN,
            ti=_agg(
                ET.DOMAIN,
                "a8f3kd9slxqz.net",
                providers=(_prov("otx", level=RL.SUSPICIOUS, score=65),),
            ),
            expect_findings=1,
        )
    )
    add(
        IocCase(
            "domain_subdomain",
            "benign_domain",
            "mail.example.org",
            ET.DOMAIN,
            ti=_agg(
                ET.DOMAIN, "mail.example.org", providers=(_prov("otx", level=RL.BENIGN, score=0),)
            ),
            expect_findings=0,
        )
    )

    # ===================================================================== #
    # URLs
    # ===================================================================== #
    add(
        IocCase(
            "url_phishing",
            "phishing_url",
            "http://secure-login.example/verify",
            ET.URL,
            ti=_agg(
                ET.URL,
                "http://secure-login.example/verify",
                providers=(_prov("urlhaus", level=RL.MALICIOUS, score=100),),
                evidence=(
                    _ev(
                        EVT.CATEGORY,
                        "Threat type: phishing",
                        value="phishing",
                        sources=("urlhaus",),
                    ),
                ),
            ),
            expect_findings=1,
            expect_categories=frozenset({FC.MALICIOUS_INFRASTRUCTURE}),
        )
    )
    add(
        IocCase(
            "url_malware_download",
            "malware_url",
            "http://evil.example/payload.exe",
            ET.URL,
            ti=_agg(
                ET.URL,
                "http://evil.example/payload.exe",
                providers=(_prov("urlhaus", level=RL.MALICIOUS, score=100),),
                evidence=(
                    _ev(
                        EVT.MALWARE_FAMILY,
                        "Malware family: Emotet",
                        value="Emotet",
                        sources=("urlhaus",),
                    ),
                ),
                relationships=(
                    _rel(RT.INDICATES, RTT.MALWARE_FAMILY, "Emotet", sources=("urlhaus",)),
                ),
            ),
            expect_findings=2,
            expect_categories=frozenset({FC.MALICIOUS_INFRASTRUCTURE, FC.MALWARE}),
        )
    )
    add(
        IocCase(
            "url_exploit_delivery",
            "malware_url",
            "http://exploit.example/kit/",
            ET.URL,
            ti=_agg(
                ET.URL,
                "http://exploit.example/kit/",
                providers=(_prov("urlhaus", level=RL.MALICIOUS, score=100),),
            ),
            expect_findings=1,
        )
    )
    add(
        IocCase(
            "url_blocklist",
            "blocklist_url",
            "http://phish.example/login",
            ET.URL,
            ti=_agg(
                ET.URL,
                "http://phish.example/login",
                providers=(_prov("openphish"),),
                evidence=(
                    _ev(
                        EVT.BLOCKLIST,
                        "Listed on OpenPhish",
                        value="listed",
                        sources=("openphish",),
                        observed_at=RECENT,
                    ),
                ),
            ),
            expect_findings=1,
            expect_overall_band=B.MODERATE,
        )
    )
    add(
        IocCase(
            "url_benign",
            "benign_url",
            "https://good.example/home",
            ET.URL,
            ti=_agg(
                ET.URL,
                "https://good.example/home",
                providers=(
                    _prov("urlhaus", status=ResultStatus.NOT_FOUND),
                    _prov("otx", level=RL.BENIGN, score=0),
                ),
            ),
            expect_findings=0,
        )
    )
    add(
        IocCase(
            "url_defanged",
            "malware_url",
            "hxxp://bad[.]com/x",
            ET.URL,
            ti=_agg(
                ET.URL,
                "hxxp://bad[.]com/x",
                providers=(_prov("urlhaus", level=RL.MALICIOUS, score=100),),
            ),
            expect_findings=1,
        )
    )
    add(
        IocCase(
            "url_with_params",
            "benign_url",
            "https://shop.example/item?id=42",
            ET.URL,
            expect_findings=0,
        )
    )
    add(
        IocCase(
            "url_unknown",
            "unknown_url",
            "http://nothing.example/path",
            ET.URL,
            ti=_agg(
                ET.URL,
                "http://nothing.example/path",
                providers=(_prov("urlhaus", status=ResultStatus.NOT_FOUND),),
            ),
            expect_findings=0,
        )
    )

    # ===================================================================== #
    # File hashes
    # ===================================================================== #
    add(
        IocCase(
            "md5_malware",
            "malware_hash",
            "44d88612fea8a8f36de82e1278abb02f",
            ET.MD5,
            ti=_agg(
                ET.MD5,
                "44d88612fea8a8f36de82e1278abb02f",
                providers=(_prov("malwarebazaar", level=RL.MALICIOUS, score=100),),
                evidence=(
                    _ev(
                        EVT.MALWARE_FAMILY,
                        "Malware family: Formbook",
                        value="Formbook",
                        sources=("malwarebazaar",),
                    ),
                ),
            ),
            expect_findings=1,
            expect_categories=frozenset({FC.MALWARE}),
        )
    )
    add(
        IocCase(
            "md5_clean",
            "clean_hash",
            "d41d8cd98f00b204e9800998ecf8427e",
            ET.MD5,
            ti=_agg(
                ET.MD5,
                "d41d8cd98f00b204e9800998ecf8427e",
                providers=(_prov("malwarebazaar", status=ResultStatus.NOT_FOUND),),
            ),
            expect_findings=0,
        )
    )
    add(
        IocCase(
            "md5_unknown",
            "unknown_hash",
            "5d41402abc4b2a76b9719d911017c592",
            ET.MD5,
            ti=_agg(
                ET.MD5,
                "5d41402abc4b2a76b9719d911017c592",
                providers=(
                    _prov("malwarebazaar", status=ResultStatus.NOT_FOUND),
                    _prov("otx", status=ResultStatus.NOT_FOUND),
                ),
            ),
            expect_findings=0,
        )
    )
    add(
        IocCase(
            "sha1_malware",
            "malware_hash",
            "da39a3ee5e6b4b0d3255bfef95601890afd80709",
            ET.SHA1,
            ti=_agg(
                ET.SHA1,
                "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                providers=(_prov("malwarebazaar", level=RL.MALICIOUS, score=100),),
                evidence=(
                    _ev(
                        EVT.MALWARE_FAMILY,
                        "Malware family: RedLine",
                        value="RedLine",
                        sources=("malwarebazaar",),
                    ),
                ),
            ),
            expect_findings=1,
            expect_categories=frozenset({FC.MALWARE}),
        )
    )
    add(
        IocCase(
            "sha1_clean",
            "clean_hash",
            "0a0a9f2a6772942557ab5355d76af442f8f65e01",
            ET.SHA1,
            ti=_agg(
                ET.SHA1,
                "0a0a9f2a6772942557ab5355d76af442f8f65e01",
                providers=(_prov("malwarebazaar", status=ResultStatus.NOT_FOUND),),
            ),
            expect_findings=0,
        )
    )
    add(
        IocCase(
            "sha256_malware",
            "malware_hash",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ET.SHA256,
            ti=_agg(
                ET.SHA256,
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                providers=(_prov("malwarebazaar", level=RL.MALICIOUS, score=100),),
                evidence=(
                    _ev(
                        EVT.MALWARE_FAMILY,
                        "Malware family: TrickBot",
                        value="TrickBot",
                        sources=("malwarebazaar",),
                    ),
                ),
                relationships=(
                    _rel(RT.INDICATES, RTT.MALWARE_FAMILY, "TrickBot", sources=("malwarebazaar",)),
                ),
            ),
            expect_findings=1,
            expect_categories=frozenset({FC.MALWARE}),
            expect_min_recommendations=2,
        )
    )
    add(
        IocCase(
            "sha256_malware_corroborated",
            "malware_hash",
            "a" * 64,
            ET.SHA256,
            ti=_agg(
                ET.SHA256,
                "a" * 64,
                providers=(
                    _prov("malwarebazaar", level=RL.MALICIOUS, score=100),
                    _prov("otx", level=RL.SUSPICIOUS, score=60),
                ),
                evidence=(
                    _ev(
                        EVT.MALWARE_FAMILY,
                        "Malware family: Qakbot",
                        value="Qakbot",
                        sources=("malwarebazaar",),
                    ),
                    _ev(
                        EVT.MALWARE_FAMILY,
                        "Malware family: Qakbot",
                        value="Qakbot",
                        sources=("otx",),
                    ),
                ),
            ),
            expect_findings=1,
            expect_categories=frozenset({FC.MALWARE}),
        )
    )
    add(
        IocCase(
            "sha256_echo_chamber",
            "malware_hash",
            "b" * 64,
            ET.SHA256,
            ti=_agg(
                ET.SHA256,
                "b" * 64,
                providers=(
                    _prov("urlhaus", level=RL.MALICIOUS, score=100),
                    _prov("malwarebazaar", level=RL.MALICIOUS, score=100),
                ),
                evidence=(
                    _ev(
                        EVT.MALWARE_FAMILY,
                        "Malware family: Dridex",
                        value="Dridex",
                        sources=("urlhaus",),
                    ),
                    _ev(
                        EVT.MALWARE_FAMILY,
                        "Malware family: Dridex",
                        value="Dridex",
                        sources=("malwarebazaar",),
                    ),
                ),
            ),
            expect_findings=1,
            expect_categories=frozenset({FC.MALWARE}),
        )
    )
    add(
        IocCase(
            "sha256_clean",
            "clean_hash",
            "c" * 64,
            ET.SHA256,
            ti=_agg(
                ET.SHA256,
                "c" * 64,
                providers=(_prov("malwarebazaar", status=ResultStatus.NOT_FOUND),),
            ),
            expect_findings=0,
        )
    )
    add(
        IocCase(
            "sha256_unknown",
            "unknown_hash",
            "d" * 64,
            ET.SHA256,
            ti=_agg(
                ET.SHA256,
                "d" * 64,
                providers=(
                    _prov("malwarebazaar", status=ResultStatus.NOT_FOUND),
                    _prov("otx", status=ResultStatus.NOT_FOUND),
                ),
            ),
            expect_findings=0,
        )
    )
    add(
        IocCase(
            "sha256_sandbox_no_family",
            "sandbox_hash",
            "e" * 64,
            ET.SHA256,
            ti=_agg(
                ET.SHA256,
                "e" * 64,
                providers=(_prov("cape"),),
                evidence=(
                    _ev(
                        EVT.SANDBOX_OBSERVATION,
                        "Writes to startup folder",
                        value="persist",
                        sources=("cape",),
                        observed_at=RECENT,
                    ),
                ),
            ),
            expect_findings=0,
        )
    )

    # ===================================================================== #
    # CVEs (NVD knowledge)
    # ===================================================================== #
    def _cve_kb(value: str, severity: str) -> AggregatedResult:
        return _agg(
            ET.CVE,
            value,
            providers=(_prov("nvd"),),
            evidence=(
                _ev(EVT.CLASSIFICATION, "Vulnerability description", sources=("nvd",)),
                _ev(EVT.CATEGORY, f"Severity: {severity}", value=severity, sources=("nvd",)),
                _ev(EVT.OTHER, "CVSS 3.1 Base Score", value="9.8", sources=("nvd",)),
            ),
            relationships=(_rel(RT.RELATED_TO, RTT.WEAKNESS, "CWE-79", sources=("nvd",)),),
        )

    add(
        IocCase(
            "cve_critical",
            "critical_cve",
            "CVE-2021-44228",
            ET.CVE,
            knowledge=_cve_kb("CVE-2021-44228", "CRITICAL"),
            expect_findings=1,
            expect_posture=S.CRITICAL,
            expect_categories=frozenset({FC.VULNERABILITY}),
            expect_min_recommendations=2,
        )
    )
    add(
        IocCase(
            "cve_high",
            "high_cve",
            "CVE-2023-23397",
            ET.CVE,
            knowledge=_cve_kb("CVE-2023-23397", "HIGH"),
            expect_findings=1,
            expect_posture=S.HIGH,
            expect_categories=frozenset({FC.VULNERABILITY}),
        )
    )
    add(
        IocCase(
            "cve_medium",
            "medium_cve",
            "CVE-2023-38831",
            ET.CVE,
            knowledge=_cve_kb("CVE-2023-38831", "MEDIUM"),
            expect_findings=0,
        )
    )
    add(
        IocCase(
            "cve_low",
            "low_cve",
            "CVE-2020-1111",
            ET.CVE,
            knowledge=_cve_kb("CVE-2020-1111", "LOW"),
            expect_findings=0,
        )
    )
    add(
        IocCase(
            "cve_recent_critical",
            "critical_cve",
            "CVE-2024-3094",
            ET.CVE,
            knowledge=_cve_kb("CVE-2024-3094", "CRITICAL"),
            expect_findings=1,
            expect_posture=S.CRITICAL,
        )
    )
    add(
        IocCase(
            "cve_historical",
            "historical_cve",
            "CVE-2014-0160",
            ET.CVE,
            knowledge=_cve_kb("CVE-2014-0160", "HIGH"),
            expect_findings=1,
            expect_posture=S.HIGH,
        )
    )
    add(
        IocCase(
            "cve_critical_corroborated",
            "critical_cve",
            "CVE-2017-0144",
            ET.CVE,
            ti=_agg(
                ET.CVE,
                "CVE-2017-0144",
                providers=(_prov("otx", level=RL.SUSPICIOUS, score=60),),
                evidence=(
                    _ev(
                        EVT.PULSE_MATCH,
                        "OTX pulse: EternalBlue",
                        value="eternalblue",
                        sources=("otx",),
                        observed_at=RECENT,
                    ),
                ),
            ),
            knowledge=_cve_kb("CVE-2017-0144", "CRITICAL"),
            expect_findings=1,
            expect_posture=S.CRITICAL,
            expect_overall_band=B.VERY_HIGH,
        )
    )
    add(
        IocCase(
            "cve_no_data",
            "unknown_cve",
            "CVE-2099-99999",
            ET.CVE,
            knowledge=_agg(
                ET.CVE, "CVE-2099-99999", providers=(_prov("nvd", status=ResultStatus.NOT_FOUND),)
            ),
            expect_findings=0,
        )
    )

    # ===================================================================== #
    # MITRE ATT&CK — techniques / actors / software
    # ===================================================================== #
    def _technique_kb(value: str) -> AggregatedResult:
        return _agg(
            ET.MITRE_TECHNIQUE,
            value,
            providers=(_prov("mitre_attack"),),
            evidence=(
                _ev(
                    EVT.CLASSIFICATION,
                    "Technique description",
                    value=value,
                    sources=("mitre_attack",),
                ),
                _ev(
                    EVT.CATEGORY, "Tactic: execution", value="execution", sources=("mitre_attack",)
                ),
            ),
            relationships=(
                _rel(RT.RELATED_TO, RTT.ATTACK_PATTERN, f"{value}.001", sources=("mitre_attack",)),
            ),
        )

    def _actor_kb(value: str, gid: str) -> AggregatedResult:
        return _agg(
            ET.THREAT_ACTOR,
            value,
            providers=(_prov("mitre_attack"),),
            evidence=(
                _ev(
                    EVT.CLASSIFICATION,
                    f"{value} group profile",
                    value=gid,
                    sources=("mitre_attack",),
                ),
                _ev(EVT.TAG, "Alias", value="alias", sources=("mitre_attack",)),
            ),
            relationships=(_rel(RT.USES, RTT.ATTACK_PATTERN, "T1566", sources=("mitre_attack",)),),
        )

    def _malware_kb(value: str, sid: str) -> AggregatedResult:
        return _agg(
            ET.MALWARE_FAMILY,
            value,
            providers=(_prov("mitre_attack"),),
            evidence=(
                _ev(
                    EVT.CLASSIFICATION, f"{value} description", value=sid, sources=("mitre_attack",)
                ),
                _ev(EVT.TAG, "Alias", value="alias", sources=("mitre_attack",)),
            ),
            relationships=(_rel(RT.USES, RTT.ATTACK_PATTERN, "T1059", sources=("mitre_attack",)),),
        )

    add(
        IocCase(
            "technique_t1059",
            "attack_technique",
            "T1059",
            ET.MITRE_TECHNIQUE,
            knowledge=_technique_kb("T1059"),
            expect_findings=1,
            expect_posture=S.MEDIUM,
            expect_categories=frozenset({FC.ATTACK_PATTERN}),
            expect_min_recommendations=2,
        )
    )
    add(
        IocCase(
            "technique_subtechnique",
            "attack_technique",
            "T1059.001",
            ET.MITRE_TECHNIQUE,
            knowledge=_technique_kb("T1059.001"),
            expect_findings=1,
            expect_categories=frozenset({FC.ATTACK_PATTERN}),
        )
    )
    add(
        IocCase(
            "technique_phishing",
            "attack_technique",
            "T1566",
            ET.MITRE_TECHNIQUE,
            knowledge=_technique_kb("T1566"),
            expect_findings=1,
            expect_categories=frozenset({FC.ATTACK_PATTERN}),
        )
    )
    add(
        IocCase(
            "technique_c2",
            "attack_technique",
            "T1071",
            ET.MITRE_TECHNIQUE,
            knowledge=_technique_kb("T1071"),
            expect_findings=1,
            expect_categories=frozenset({FC.ATTACK_PATTERN}),
        )
    )
    add(
        IocCase(
            "actor_apt28",
            "threat_actor",
            "APT28",
            ET.THREAT_ACTOR,
            knowledge=_actor_kb("APT28", "G0007"),
            expect_findings=2,
            expect_posture=S.MEDIUM,
            expect_categories=frozenset({FC.THREAT_ACTOR, FC.ATTACK_PATTERN}),
        )
    )
    add(
        IocCase(
            "actor_apt29",
            "threat_actor",
            "APT29",
            ET.THREAT_ACTOR,
            knowledge=_actor_kb("APT29", "G0016"),
            expect_categories=frozenset({FC.THREAT_ACTOR}),
        )
    )
    add(
        IocCase(
            "actor_lazarus",
            "threat_actor",
            "Lazarus Group",
            ET.THREAT_ACTOR,
            knowledge=_actor_kb("Lazarus Group", "G0032"),
            expect_categories=frozenset({FC.THREAT_ACTOR}),
        )
    )
    add(
        IocCase(
            "malware_emotet",
            "malware_family",
            "emotet",
            ET.MALWARE_FAMILY,
            knowledge=_malware_kb("emotet", "S0367"),
            expect_findings=2,
            expect_posture=S.HIGH,
            expect_categories=frozenset({FC.MALWARE, FC.ATTACK_PATTERN}),
        )
    )
    add(
        IocCase(
            "malware_trickbot",
            "malware_family",
            "trickbot",
            ET.MALWARE_FAMILY,
            knowledge=_malware_kb("trickbot", "S0266"),
            expect_categories=frozenset({FC.MALWARE}),
        )
    )
    add(
        IocCase(
            "malware_mimikatz",
            "malware_family",
            "mimikatz",
            ET.MALWARE_FAMILY,
            knowledge=_malware_kb("mimikatz", "S0002"),
            expect_categories=frozenset({FC.MALWARE}),
        )
    )
    add(
        IocCase(
            "malware_cobaltstrike",
            "malware_family",
            "Cobalt Strike",
            ET.MALWARE_FAMILY,
            knowledge=_malware_kb("Cobalt Strike", "S0154"),
            expect_categories=frozenset({FC.MALWARE}),
        )
    )

    # ===================================================================== #
    # CWE / CAPEC knowledge
    # ===================================================================== #
    def _cwe_kb(value: str) -> AggregatedResult:
        return _agg(
            ET.CWE,
            value,
            providers=(_prov("cwe"),),
            evidence=(
                _ev(EVT.CLASSIFICATION, "Weakness description", value=value, sources=("cwe",)),
                _ev(EVT.CATEGORY, "Abstraction: Base", value="Base", sources=("cwe",)),
            ),
            relationships=(
                _rel(RT.RELATED_TO, RTT.WEAKNESS, "CWE-20", sources=("cwe",)),
                _rel(RT.RELATED_TO, RTT.ATTACK_PATTERN, "CAPEC-63", sources=("cwe",)),
            ),
        )

    def _capec_kb(value: str) -> AggregatedResult:
        return _agg(
            ET.CAPEC,
            value,
            providers=(_prov("capec"),),
            evidence=(
                _ev(
                    EVT.CLASSIFICATION,
                    "Attack pattern description",
                    value=value,
                    sources=("capec",),
                ),
                _ev(EVT.CATEGORY, "Likelihood: High", value="High", sources=("capec",)),
            ),
            relationships=(
                _rel(RT.EXPLOITS, RTT.WEAKNESS, "CWE-94", sources=("capec",)),
                _rel(RT.RELATED_TO, RTT.ATTACK_PATTERN, "T1059", sources=("capec",)),
            ),
        )

    add(
        IocCase(
            "cwe_79",
            "weakness",
            "CWE-79",
            ET.CWE,
            knowledge=_cwe_kb("CWE-79"),
            expect_findings=1,
            expect_categories=frozenset({FC.ATTACK_PATTERN}),
        )
    )
    add(
        IocCase(
            "cwe_89",
            "weakness",
            "CWE-89",
            ET.CWE,
            knowledge=_cwe_kb("CWE-89"),
            expect_findings=1,
            expect_categories=frozenset({FC.ATTACK_PATTERN}),
        )
    )
    add(
        IocCase(
            "cwe_787",
            "weakness",
            "CWE-787",
            ET.CWE,
            knowledge=_cwe_kb("CWE-787"),
            expect_findings=1,
        )
    )
    add(
        IocCase(
            "capec_242",
            "attack_pattern",
            "CAPEC-242",
            ET.CAPEC,
            knowledge=_capec_kb("CAPEC-242"),
            expect_findings=1,
            expect_categories=frozenset({FC.ATTACK_PATTERN}),
        )
    )
    add(
        IocCase(
            "capec_66",
            "attack_pattern",
            "CAPEC-66",
            ET.CAPEC,
            knowledge=_capec_kb("CAPEC-66"),
            expect_findings=1,
        )
    )
    add(
        IocCase(
            "capec_63",
            "attack_pattern",
            "CAPEC-63",
            ET.CAPEC,
            knowledge=_capec_kb("CAPEC-63"),
            expect_findings=1,
        )
    )

    # ===================================================================== #
    # Additional real-world coverage
    # ===================================================================== #
    add(
        IocCase(
            "ip_tor_exit",
            "suspicious_ip",
            "204.13.164.10",
            ET.IPV4,
            ti=_agg(
                ET.IPV4,
                "204.13.164.10",
                providers=(_prov("otx", level=RL.SUSPICIOUS, score=50),),
                evidence=(_ev(EVT.TAG, "Tag: tor", value="tor", sources=("otx",)),),
            ),
            expect_findings=1,
        )
    )
    add(
        IocCase(
            "ip_bruteforce",
            "malicious_ip",
            "141.98.10.20",
            ET.IPV4,
            ti=_agg(
                ET.IPV4,
                "141.98.10.20",
                providers=(_prov("abuseipdb", level=RL.MALICIOUS, score=100),),
                evidence=(
                    _ev(
                        EVT.CATEGORY,
                        "Reported for: SSH Bruteforce",
                        value="ssh",
                        sources=("abuseipdb",),
                    ),
                ),
            ),
            expect_findings=1,
            expect_categories=frozenset({FC.MALICIOUS_INFRASTRUCTURE}),
        )
    )
    add(
        IocCase(
            "ip_botnet_c2",
            "malicious_ip",
            "185.100.87.20",
            ET.IPV4,
            ti=_agg(
                ET.IPV4,
                "185.100.87.20",
                providers=(_prov("abuseipdb", level=RL.MALICIOUS, score=95),),
                relationships=(_rel(RT.INDICATES, RTT.MALWARE_FAMILY, "Mirai", sources=("otx",)),),
            ),
            expect_findings=2,
            expect_categories=frozenset({FC.MALICIOUS_INFRASTRUCTURE, FC.MALWARE}),
        )
    )
    add(
        IocCase(
            "ip_multi_source",
            "malicious_ip",
            "89.248.165.30",
            ET.IPV4,
            ti=_agg(
                ET.IPV4,
                "89.248.165.30",
                providers=(
                    _prov("abuseipdb", level=RL.MALICIOUS, score=100),
                    _prov("otx", level=RL.SUSPICIOUS, score=60),
                    _prov("greynoise", level=RL.MALICIOUS, score=90),
                ),
            ),
            expect_findings=1,
            expect_categories=frozenset({FC.MALICIOUS_INFRASTRUCTURE}),
        )
    )
    add(
        IocCase(
            "domain_phishing_kit",
            "phishing_domain",
            "login-verify-account.com",
            ET.DOMAIN,
            ti=_agg(
                ET.DOMAIN,
                "login-verify-account.com",
                providers=(_prov("urlhaus", level=RL.MALICIOUS, score=100),),
                evidence=(
                    _ev(
                        EVT.CATEGORY,
                        "Threat type: phishing",
                        value="phishing",
                        sources=("urlhaus",),
                    ),
                ),
            ),
            expect_findings=1,
        )
    )
    add(
        IocCase(
            "domain_malvertising",
            "suspicious_domain",
            "ads-tracker-cdn.com",
            ET.DOMAIN,
            ti=_agg(
                ET.DOMAIN,
                "ads-tracker-cdn.com",
                providers=(_prov("otx", level=RL.SUSPICIOUS, score=50),),
            ),
            expect_findings=1,
        )
    )
    add(
        IocCase(
            "domain_legit_bank",
            "benign_domain",
            "chase.com",
            ET.DOMAIN,
            ti=_agg(ET.DOMAIN, "chase.com", providers=(_prov("otx", level=RL.BENIGN, score=0),)),
            expect_findings=0,
        )
    )
    add(
        IocCase(
            "url_credential_harvest",
            "phishing_url",
            "http://verify-account.com/login",
            ET.URL,
            ti=_agg(
                ET.URL,
                "http://verify-account.com/login",
                providers=(_prov("urlhaus", level=RL.MALICIOUS, score=100),),
                evidence=(
                    _ev(
                        EVT.CATEGORY,
                        "Threat type: phishing",
                        value="phishing",
                        sources=("urlhaus",),
                    ),
                ),
            ),
            expect_findings=1,
        )
    )
    add(
        IocCase(
            "url_drive_by",
            "malware_url",
            "http://cdn-delivery.net/js/loader.js",
            ET.URL,
            ti=_agg(
                ET.URL,
                "http://cdn-delivery.net/js/loader.js",
                providers=(_prov("urlhaus", level=RL.MALICIOUS, score=100),),
            ),
            expect_findings=1,
        )
    )
    add(
        IocCase(
            "md5_ransomware",
            "malware_hash",
            "f" * 32,
            ET.MD5,
            ti=_agg(
                ET.MD5,
                "f" * 32,
                providers=(_prov("malwarebazaar", level=RL.MALICIOUS, score=100),),
                evidence=(
                    _ev(
                        EVT.MALWARE_FAMILY,
                        "Malware family: LockBit",
                        value="LockBit",
                        sources=("malwarebazaar",),
                    ),
                ),
            ),
            expect_findings=1,
            expect_categories=frozenset({FC.MALWARE}),
        )
    )
    add(
        IocCase(
            "sha256_apt_tool",
            "malware_hash",
            "1" * 64,
            ET.SHA256,
            ti=_agg(
                ET.SHA256,
                "1" * 64,
                providers=(_prov("malwarebazaar", level=RL.MALICIOUS, score=100),),
                evidence=(
                    _ev(
                        EVT.MALWARE_FAMILY,
                        "Malware family: Cobalt Strike",
                        value="Cobalt Strike",
                        sources=("malwarebazaar",),
                    ),
                ),
                relationships=(
                    _rel(
                        RT.INDICATES,
                        RTT.MALWARE_FAMILY,
                        "Cobalt Strike",
                        sources=("malwarebazaar",),
                    ),
                ),
            ),
            expect_findings=1,
            expect_categories=frozenset({FC.MALWARE}),
        )
    )
    add(
        IocCase(
            "cve_high_recent",
            "high_cve",
            "CVE-2024-21413",
            ET.CVE,
            knowledge=_cve_kb("CVE-2024-21413", "HIGH"),
            expect_findings=1,
            expect_posture=S.HIGH,
        )
    )
    add(
        IocCase(
            "cve_critical_kev",
            "critical_cve",
            "CVE-2023-34362",
            ET.CVE,
            knowledge=_cve_kb("CVE-2023-34362", "CRITICAL"),
            expect_findings=1,
            expect_posture=S.CRITICAL,
        )
    )
    add(
        IocCase(
            "technique_persistence",
            "attack_technique",
            "T1547",
            ET.MITRE_TECHNIQUE,
            knowledge=_technique_kb("T1547"),
            expect_findings=1,
            expect_categories=frozenset({FC.ATTACK_PATTERN}),
        )
    )
    add(
        IocCase(
            "actor_ta505",
            "threat_actor",
            "TA505",
            ET.THREAT_ACTOR,
            knowledge=_actor_kb("TA505", "G0092"),
            expect_findings=2,
            expect_categories=frozenset({FC.THREAT_ACTOR, FC.ATTACK_PATTERN}),
        )
    )

    # ===================================================================== #
    # Supported entities with no investigation providers (graceful, no findings)
    # ===================================================================== #
    add(IocCase("email_address", "no_provider", "user@example.com", ET.EMAIL, expect_findings=0))
    add(IocCase("process_name", "no_provider", "rundll32.exe", ET.PROCESS_NAME, expect_findings=0))
    add(
        IocCase(
            "registry_key",
            "no_provider",
            r"HKLM\Software\Microsoft\Run",
            ET.REGISTRY_KEY,
            expect_findings=0,
        )
    )
    add(
        IocCase(
            "powershell_command",
            "no_provider",
            "Invoke-Mimikatz",
            ET.POWERSHELL_COMMAND,
            expect_findings=0,
        )
    )

    # ===================================================================== #
    # Invalid / edge inputs
    # ===================================================================== #
    add(
        IocCase(
            "freetext_random",
            "freetext",
            "not a real indicator 123",
            ET.FREETEXT,
            expect_findings=0,
        )
    )
    add(
        IocCase(
            "freetext_sentence",
            "freetext",
            "please investigate this host for me",
            ET.FREETEXT,
            expect_findings=0,
        )
    )
    add(IocCase("unknown_symbols", "unknown", "%%%%%%", ET.UNKNOWN, expect_findings=0))
    add(IocCase("unknown_unicode", "unknown", "☠☠☠", ET.UNKNOWN, expect_findings=0))
    add(IocCase("invalid_empty", "invalid_input", "", ET.UNKNOWN, api_status=422))
    add(IocCase("invalid_blank", "invalid_input", "    ", ET.UNKNOWN, api_status=422))
    add(IocCase("invalid_oversized", "invalid_input", "A" * 5000, ET.UNKNOWN, api_status=422))

    return tuple(cases)


CORPUS: tuple[IocCase, ...] = _build()


# Guard against accidental id collisions (which would silently mask a case).
_seen: set[str] = set()
for _case in CORPUS:
    if _case.id in _seen:
        raise ValueError(f"duplicate IOC case id: {_case.id}")
    _seen.add(_case.id)
del _seen
