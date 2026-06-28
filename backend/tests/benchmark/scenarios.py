"""The benchmark corpus: deterministic investigation scenarios + expectations.

Every scenario constructs synthetic :class:`AggregatedResult` inputs (TI +
knowledge) that mirror what the real providers emit — exact ``EvidenceType`` /
``RelationshipTargetType`` / ``ReputationLevel`` combinations — and declares the
expected engine output. Expectations are hand-derived from the frozen confidence
model (Authority 0.35 · Agreement 0.25 · Corroboration 0.25 · Freshness 0.15;
corroboration counts authority *families*) and the derived-priority model
(``severity_base = (4 - severity) * 100``; ``confidence_penalty = (4 - band) *
10``; minus a non-negative context boost; clamped ≥ 0).

All inputs are evaluated at a single fixed ``NOW`` so freshness is deterministic.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from threatlens.entities.models import Entity
from threatlens.entities.types import EntityType, ValidationStatus
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
from threatlens.reasoning import (
    EMPTY_CONTEXT,
    AssetCriticality,
    ConfidenceBand,
    Environment,
    FindingCategory,
    InvestigationContext,
    RecommendationAction,
    Severity,
)

# Single fixed reference time → deterministic freshness for every scenario.
NOW = datetime(2025, 1, 1, tzinfo=UTC)
RECENT = NOW - timedelta(days=5)  # full freshness (≤ 30 days)
STALE = NOW - timedelta(days=400)  # decayed to the freshness floor (≥ 365 days)


# --------------------------------------------------------------------------- #
# Construction helpers
# --------------------------------------------------------------------------- #


def _entity(entity_type: EntityType, value: str) -> Entity:
    return Entity(
        type=entity_type,
        value=value,
        normalized_value=value,
        confidence=100,
        validation=ValidationStatus.VALID,
        possible_matches=[],
    )


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
# Expectation model
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class ExpectedFinding:
    """A single expected finding, matched to an actual finding by category+severity."""

    category: FindingCategory  # must be present in the finding's category set
    severity: Severity
    band: ConfidenceBand
    contested: bool = False
    priority: int | None = None  # exact derived priority (checked when provided)
    min_recommendations: int = 0


@dataclass(frozen=True)
class Scenario:
    """One deterministic benchmark case and its pinned expected output."""

    id: str
    kind: str
    description: str
    entity: Entity
    ti: AggregatedResult
    knowledge: AggregatedResult
    posture: Severity
    overall_band: ConfidenceBand
    findings: tuple[ExpectedFinding, ...] = ()
    # Ordered rollup actions (the deterministic-ordering guarantee). None = unchecked.
    rollup: tuple[RecommendationAction, ...] | None = None
    context: InvestigationContext = EMPTY_CONTEXT
    overall_contested: bool | None = None  # checked when provided

    @property
    def finding_count(self) -> int:
        return len(self.findings)


# Shorthand
EF = ExpectedFinding
B = ConfidenceBand
S = Severity
FC = FindingCategory
RA = RecommendationAction


def _build() -> tuple[Scenario, ...]:  # noqa: C901 - a long but flat data table
    scenarios: list[Scenario] = []
    add = scenarios.append

    # ===================================================================== #
    # IP reputation (abuseipdb 0.60 · otx 0.60 · community 0.40)
    # ===================================================================== #

    add(
        Scenario(
            id="ip_benign",
            kind="Benign IPv4",
            description="abuseipdb reports the IP benign; no supporting signal → no finding.",
            entity=_entity(EntityType.IPV4, "8.8.8.8"),
            ti=_agg(
                EntityType.IPV4,
                "8.8.8.8",
                providers=(_prov("abuseipdb", level=ReputationLevel.BENIGN, score=0),),
                evidence=(_ev(EvidenceType.OTHER, "ISP: Google", sources=("abuseipdb",)),),
            ),
            knowledge=_empty(EntityType.IPV4, "8.8.8.8"),
            posture=S.INFORMATIONAL,
            overall_band=B.INSUFFICIENT,
            overall_contested=True,  # a benign verdict is a contradiction with no support
        )
    )
    add(
        Scenario(
            id="ip_malicious_single",
            kind="Malicious IPv4",
            description="Single mid-authority malicious verdict + abuse-confidence evidence.",
            entity=_entity(EntityType.IPV4, "45.155.205.233"),
            ti=_agg(
                EntityType.IPV4,
                "45.155.205.233",
                providers=(_prov("abuseipdb", level=ReputationLevel.MALICIOUS, score=100),),
                evidence=(
                    _ev(
                        EvidenceType.ABUSE_CONFIDENCE,
                        "Abuse confidence score: 100%",
                        value="100%",
                        sources=("abuseipdb",),
                        observed_at=RECENT,
                    ),
                ),
            ),
            knowledge=_empty(EntityType.IPV4, "45.155.205.233"),
            posture=S.HIGH,
            overall_band=B.HIGH,  # 0.35*0.6 + 0.25 + 0 + 0.15 = 0.61
            findings=(
                EF(
                    FC.MALICIOUS_INFRASTRUCTURE, S.HIGH, B.HIGH, priority=110, min_recommendations=2
                ),
            ),
            rollup=(RA.BLOCK, RA.THREAT_HUNT),
        )
    )
    add(
        Scenario(
            id="ip_suspicious_single",
            kind="Suspicious IPv4",
            description="A single OTX suspicious verdict still supports a malicious-infra finding.",
            entity=_entity(EntityType.IPV4, "193.0.0.1"),
            ti=_agg(
                EntityType.IPV4,
                "193.0.0.1",
                providers=(_prov("otx", level=ReputationLevel.SUSPICIOUS, score=50),),
            ),
            knowledge=_empty(EntityType.IPV4, "193.0.0.1"),
            posture=S.HIGH,
            overall_band=B.HIGH,
            findings=(EF(FC.MALICIOUS_INFRASTRUCTURE, S.HIGH, B.HIGH, priority=110),),
            rollup=(RA.BLOCK, RA.THREAT_HUNT),
        )
    )
    add(
        Scenario(
            id="ip_malicious_two_families",
            kind="Malicious IPv4 (corroborated)",
            description="abuseipdb + OTX (two independent families) raise corroboration.",
            entity=_entity(EntityType.IPV4, "45.155.205.234"),
            ti=_agg(
                EntityType.IPV4,
                "45.155.205.234",
                providers=(
                    _prov("abuseipdb", level=ReputationLevel.MALICIOUS, score=100),
                    _prov("otx", level=ReputationLevel.SUSPICIOUS, score=60),
                ),
            ),
            knowledge=_empty(EntityType.IPV4, "45.155.205.234"),
            posture=S.HIGH,
            overall_band=B.HIGH,  # corroboration 0.5 → ~74, still HIGH (TI maxes at HIGH)
            findings=(EF(FC.MALICIOUS_INFRASTRUCTURE, S.HIGH, B.HIGH),),
        )
    )
    add(
        Scenario(
            id="ip_contested",
            kind="Conflicting evidence (IPv4)",
            description="One malicious and one benign verdict → contested, capped at MODERATE.",
            entity=_entity(EntityType.IPV4, "1.2.3.4"),
            ti=_agg(
                EntityType.IPV4,
                "1.2.3.4",
                providers=(
                    _prov("abuseipdb", level=ReputationLevel.MALICIOUS, score=90),
                    _prov("otx", level=ReputationLevel.BENIGN, score=0),
                ),
            ),
            knowledge=_empty(EntityType.IPV4, "1.2.3.4"),
            posture=S.HIGH,
            overall_band=B.MODERATE,
            findings=(
                EF(FC.MALICIOUS_INFRASTRUCTURE, S.HIGH, B.MODERATE, contested=True, priority=120),
            ),
            rollup=(RA.BLOCK, RA.THREAT_HUNT),
        )
    )
    add(
        Scenario(
            id="ip_majority_malicious_minor_benign",
            kind="Conflicting evidence (minority benign)",
            description="Two malicious vs one weak likely-benign → not contested (ratio < 0.25).",
            entity=_entity(EntityType.IPV4, "5.6.7.8"),
            ti=_agg(
                EntityType.IPV4,
                "5.6.7.8",
                providers=(
                    _prov("abuseipdb", level=ReputationLevel.MALICIOUS, score=95),
                    _prov("otx", level=ReputationLevel.SUSPICIOUS, score=60),
                    _prov("greynoise", level=ReputationLevel.LIKELY_BENIGN, score=20),
                ),
            ),
            knowledge=_empty(EntityType.IPV4, "5.6.7.8"),
            posture=S.HIGH,
            overall_band=B.HIGH,
            findings=(EF(FC.MALICIOUS_INFRASTRUCTURE, S.HIGH, B.HIGH, contested=False),),
        )
    )
    add(
        Scenario(
            id="ip_fresh_detection",
            kind="Fresh evidence (IPv4)",
            description="A single recent detection (no reputation verdict) → HIGH.",
            entity=_entity(EntityType.IPV4, "9.9.9.10"),
            ti=_agg(
                EntityType.IPV4,
                "9.9.9.10",
                providers=(_prov("otx"),),
                evidence=(
                    _ev(
                        EvidenceType.DETECTION,
                        "C2 beacon detected",
                        value="c2",
                        sources=("otx",),
                        observed_at=RECENT,
                    ),
                ),
            ),
            knowledge=_empty(EntityType.IPV4, "9.9.9.10"),
            posture=S.HIGH,
            overall_band=B.HIGH,  # freshness 1.0 → 0.21 + 0.25 + 0 + 0.15 = 0.61
            findings=(EF(FC.MALICIOUS_INFRASTRUCTURE, S.HIGH, B.HIGH),),
        )
    )
    add(
        Scenario(
            id="ip_stale_detection",
            kind="Stale evidence (IPv4)",
            description="The same detection observed 400 days ago decays HIGH → MODERATE.",
            entity=_entity(EntityType.IPV4, "9.9.9.11"),
            ti=_agg(
                EntityType.IPV4,
                "9.9.9.11",
                providers=(_prov("otx"),),
                evidence=(
                    _ev(
                        EvidenceType.DETECTION,
                        "C2 beacon detected",
                        value="c2",
                        sources=("otx",),
                        observed_at=STALE,
                    ),
                ),
            ),
            knowledge=_empty(EntityType.IPV4, "9.9.9.11"),
            posture=S.HIGH,
            overall_band=B.MODERATE,  # freshness floor 0.3 → 0.21 + 0.25 + 0 + 0.045 = 0.505
            findings=(EF(FC.MALICIOUS_INFRASTRUCTURE, S.HIGH, B.MODERATE),),
        )
    )
    add(
        Scenario(
            id="ip_reputation_timeless_over_stale_detection",
            kind="Timeless reputation keeps freshness",
            description="A timeless verdict keeps freshness 1.0 despite a stale detection.",
            entity=_entity(EntityType.IPV4, "9.9.9.12"),
            ti=_agg(
                EntityType.IPV4,
                "9.9.9.12",
                providers=(_prov("abuseipdb", level=ReputationLevel.MALICIOUS, score=100),),
                evidence=(
                    _ev(
                        EvidenceType.DETECTION,
                        "Old detection",
                        value="old",
                        sources=("abuseipdb",),
                        observed_at=STALE,
                    ),
                ),
            ),
            knowledge=_empty(EntityType.IPV4, "9.9.9.12"),
            posture=S.HIGH,
            overall_band=B.HIGH,  # the undated reputation contributes freshness 1.0
            findings=(EF(FC.MALICIOUS_INFRASTRUCTURE, S.HIGH, B.HIGH),),
        )
    )
    add(
        Scenario(
            id="ip_low_confidence_refuted",
            kind="Sparse + contradicted + stale (IPv4)",
            description="A weak stale detection refuted by two benign verdicts → LOW, no recs.",
            entity=_entity(EntityType.IPV4, "9.9.9.13"),
            ti=_agg(
                EntityType.IPV4,
                "9.9.9.13",
                providers=(
                    _prov("greynoise", level=ReputationLevel.BENIGN, score=0),
                    _prov("censys", level=ReputationLevel.BENIGN, score=0),
                ),
                evidence=(
                    _ev(
                        EvidenceType.DETECTION,
                        "Weak old detection",
                        value="weak",
                        sources=("randomfeed",),
                        observed_at=STALE,
                    ),
                ),
            ),
            knowledge=_empty(EntityType.IPV4, "9.9.9.13"),
            posture=S.HIGH,
            overall_band=B.LOW,  # below MODERATE → recommendation gate not met
            findings=(
                EF(
                    FC.MALICIOUS_INFRASTRUCTURE,
                    S.HIGH,
                    B.LOW,
                    contested=True,
                    min_recommendations=0,
                ),
            ),
            rollup=(),  # confidence below MODERATE → no recommendations generated
        )
    )
    add(
        Scenario(
            id="ip_contextual_only",
            kind="Contextual evidence only (IPv4)",
            description="Only geolocation/ISP context, no reputation → no finding.",
            entity=_entity(EntityType.IPV4, "13.13.13.13"),
            ti=_agg(
                EntityType.IPV4,
                "13.13.13.13",
                providers=(_prov("abuseipdb"),),
                evidence=(
                    _ev(EvidenceType.OTHER, "Country: US", sources=("abuseipdb",)),
                    _ev(EvidenceType.OTHER, "ISP: ExampleNet", sources=("abuseipdb",)),
                ),
            ),
            knowledge=_empty(EntityType.IPV4, "13.13.13.13"),
            posture=S.INFORMATIONAL,
            overall_band=B.INSUFFICIENT,
        )
    )
    add(
        Scenario(
            id="ipv6_malicious",
            kind="Malicious IPv6",
            description="IPv6 routes through the same malicious-infrastructure rule.",
            entity=_entity(EntityType.IPV6, "2001:db8::dead:beef"),
            ti=_agg(
                EntityType.IPV6,
                "2001:db8::dead:beef",
                providers=(_prov("abuseipdb", level=ReputationLevel.MALICIOUS, score=100),),
            ),
            knowledge=_empty(EntityType.IPV6, "2001:db8::dead:beef"),
            posture=S.HIGH,
            overall_band=B.HIGH,
            findings=(EF(FC.MALICIOUS_INFRASTRUCTURE, S.HIGH, B.HIGH),),
            rollup=(RA.BLOCK, RA.THREAT_HUNT),
        )
    )

    # --- Context (priority only — never severity/confidence/findings) -------- #
    _ip_ctx_ti = _agg(
        EntityType.IPV4,
        "45.155.205.233",
        providers=(_prov("abuseipdb", level=ReputationLevel.MALICIOUS, score=100),),
        evidence=(
            _ev(
                EvidenceType.ABUSE_CONFIDENCE,
                "Abuse confidence score: 100%",
                value="100%",
                sources=("abuseipdb",),
                observed_at=RECENT,
            ),
        ),
    )
    add(
        Scenario(
            id="ip_malicious_internet_facing_ctx",
            kind="Context: internet-facing",
            description="internet_facing raises urgency (priority only) vs ip_malicious_single.",
            entity=_entity(EntityType.IPV4, "45.155.205.233"),
            ti=_ip_ctx_ti,
            knowledge=_empty(EntityType.IPV4, "45.155.205.233"),
            posture=S.HIGH,
            overall_band=B.HIGH,
            findings=(EF(FC.MALICIOUS_INFRASTRUCTURE, S.HIGH, B.HIGH, priority=90),),  # 110 - 20
            context=InvestigationContext(internet_facing=True),
        )
    )
    add(
        Scenario(
            id="ip_malicious_prod_critical_ctx",
            kind="Context: critical production asset",
            description="critical + production + internet (boost 80) shifts priority 110 → 30.",
            entity=_entity(EntityType.IPV4, "45.155.205.233"),
            ti=_ip_ctx_ti,
            knowledge=_empty(EntityType.IPV4, "45.155.205.233"),
            posture=S.HIGH,
            overall_band=B.HIGH,
            findings=(EF(FC.MALICIOUS_INFRASTRUCTURE, S.HIGH, B.HIGH, priority=30),),
            context=InvestigationContext(
                criticality=AssetCriticality.CRITICAL,
                environment=Environment.PRODUCTION,
                internet_facing=True,
            ),
        )
    )

    # ===================================================================== #
    # Domains & URLs (urlhaus 0.70 abuse.ch · otx 0.60)
    # ===================================================================== #

    add(
        Scenario(
            id="url_malicious_urlhaus",
            kind="Malicious URL",
            description="URLhaus malicious URL with a malware family → infra + malware findings.",
            entity=_entity(EntityType.URL, "http://evil.example/payload.exe"),
            ti=_agg(
                EntityType.URL,
                "http://evil.example/payload.exe",
                providers=(_prov("urlhaus", level=ReputationLevel.MALICIOUS, score=100),),
                evidence=(
                    _ev(
                        EvidenceType.CATEGORY,
                        "Threat type: malware_download",
                        value="malware_download",
                        sources=("urlhaus",),
                    ),
                    _ev(
                        EvidenceType.MALWARE_FAMILY,
                        "Malware family: Emotet",
                        value="Emotet",
                        sources=("urlhaus",),
                    ),
                ),
                relationships=(
                    _rel(
                        RelationshipType.INDICATES,
                        RelationshipTargetType.MALWARE_FAMILY,
                        "Emotet",
                        sources=("urlhaus",),
                    ),
                ),
            ),
            knowledge=_empty(EntityType.URL, "http://evil.example/payload.exe"),
            posture=S.HIGH,
            overall_band=B.HIGH,
            findings=(
                EF(FC.MALICIOUS_INFRASTRUCTURE, S.HIGH, B.HIGH),
                EF(FC.MALWARE, S.HIGH, B.HIGH),
            ),
            # Two findings both emit BLOCK on the same URL → merged once in the rollup.
            rollup=(RA.BLOCK, RA.INVESTIGATE, RA.THREAT_HUNT),
        )
    )
    add(
        Scenario(
            id="url_blocklist_low_authority",
            kind="Blocklisted URL (low authority)",
            description="A single low-authority blocklist hit → MODERATE confidence.",
            entity=_entity(EntityType.URL, "http://phish.example/login"),
            ti=_agg(
                EntityType.URL,
                "http://phish.example/login",
                providers=(_prov("openphish"),),
                evidence=(
                    _ev(
                        EvidenceType.BLOCKLIST,
                        "Listed on OpenPhish",
                        value="listed",
                        sources=("openphish",),
                        observed_at=RECENT,
                    ),
                ),
            ),
            knowledge=_empty(EntityType.URL, "http://phish.example/login"),
            posture=S.HIGH,
            overall_band=B.MODERATE,  # authority 0.4 → 0.14 + 0.25 + 0 + 0.15 = 0.54
            findings=(EF(FC.MALICIOUS_INFRASTRUCTURE, S.HIGH, B.MODERATE, min_recommendations=2),),
            rollup=(RA.BLOCK, RA.THREAT_HUNT),
        )
    )
    add(
        Scenario(
            id="domain_benign",
            kind="Benign domain",
            description="A benign verdict on a domain yields no finding.",
            entity=_entity(EntityType.DOMAIN, "example.com"),
            ti=_agg(
                EntityType.DOMAIN,
                "example.com",
                providers=(_prov("otx", level=ReputationLevel.BENIGN, score=0),),
            ),
            knowledge=_empty(EntityType.DOMAIN, "example.com"),
            posture=S.INFORMATIONAL,
            overall_band=B.INSUFFICIENT,
            overall_contested=True,
        )
    )
    add(
        Scenario(
            id="domain_otx_full",
            kind="Multiple findings (domain)",
            description="OTX domain with malware, actor and technique links → four findings.",
            entity=_entity(EntityType.DOMAIN, "bad.example.org"),
            ti=_agg(
                EntityType.DOMAIN,
                "bad.example.org",
                providers=(_prov("otx", level=ReputationLevel.SUSPICIOUS, score=60),),
                evidence=(
                    _ev(
                        EvidenceType.PULSE_MATCH,
                        "OTX pulse: APT campaign",
                        value="apt",
                        sources=("otx",),
                        observed_at=RECENT,
                    ),
                    _ev(
                        EvidenceType.MALWARE_FAMILY,
                        "Malware family: Emotet",
                        value="Emotet",
                        sources=("otx",),
                    ),
                ),
                relationships=(
                    _rel(
                        RelationshipType.INDICATES,
                        RelationshipTargetType.MALWARE_FAMILY,
                        "Emotet",
                        sources=("otx",),
                    ),
                    _rel(
                        RelationshipType.ATTRIBUTED_TO,
                        RelationshipTargetType.THREAT_ACTOR,
                        "APT28",
                        sources=("otx",),
                    ),
                    _rel(
                        RelationshipType.USES,
                        RelationshipTargetType.ATTACK_PATTERN,
                        "T1566",
                        sources=("otx",),
                    ),
                ),
            ),
            knowledge=_empty(EntityType.DOMAIN, "bad.example.org"),
            posture=S.HIGH,
            overall_band=B.HIGH,
            findings=(
                EF(FC.MALICIOUS_INFRASTRUCTURE, S.HIGH, B.HIGH),
                EF(FC.MALWARE, S.HIGH, B.HIGH),
                EF(FC.THREAT_ACTOR, S.MEDIUM, B.HIGH),
                EF(FC.ATTACK_PATTERN, S.MEDIUM, B.HIGH),
            ),
        )
    )
    add(
        Scenario(
            id="domain_attributed_actor_benign_rep",
            kind="Attribution without malicious reputation",
            description="Attribution yields a threat-actor finding despite a benign reputation.",
            entity=_entity(EntityType.DOMAIN, "cdn.example.net"),
            ti=_agg(
                EntityType.DOMAIN,
                "cdn.example.net",
                providers=(_prov("otx", level=ReputationLevel.BENIGN, score=0),),
                relationships=(
                    _rel(
                        RelationshipType.ATTRIBUTED_TO,
                        RelationshipTargetType.THREAT_ACTOR,
                        "APT29",
                        sources=("otx",),
                    ),
                ),
            ),
            knowledge=_empty(EntityType.DOMAIN, "cdn.example.net"),
            posture=S.MEDIUM,
            overall_band=B.HIGH,
            findings=(EF(FC.THREAT_ACTOR, S.MEDIUM, B.HIGH, min_recommendations=2),),
            rollup=(RA.INVESTIGATE, RA.ENRICH),
        )
    )
    add(
        Scenario(
            id="ip_technique_relationship",
            kind="Technique link on a benign IP",
            description="Technique relationship → attack-pattern finding on a benign IP.",
            entity=_entity(EntityType.IPV4, "10.20.30.40"),
            ti=_agg(
                EntityType.IPV4,
                "10.20.30.40",
                providers=(_prov("otx", level=ReputationLevel.BENIGN, score=0),),
                relationships=(
                    _rel(
                        RelationshipType.USES,
                        RelationshipTargetType.ATTACK_PATTERN,
                        "T1071",
                        sources=("otx",),
                    ),
                ),
            ),
            knowledge=_empty(EntityType.IPV4, "10.20.30.40"),
            posture=S.MEDIUM,
            overall_band=B.HIGH,
            findings=(EF(FC.ATTACK_PATTERN, S.MEDIUM, B.HIGH),),
        )
    )

    # ===================================================================== #
    # File hashes (malwarebazaar 0.70 abuse.ch · otx 0.60 · community 0.40)
    # ===================================================================== #

    _hash = "a" * 64
    add(
        Scenario(
            id="hash_malware_mwb",
            kind="Malware hash",
            description="MalwareBazaar hash with a family attribution → malware finding.",
            entity=_entity(EntityType.SHA256, _hash),
            ti=_agg(
                EntityType.SHA256,
                _hash,
                providers=(_prov("malwarebazaar", level=ReputationLevel.MALICIOUS, score=100),),
                evidence=(
                    _ev(
                        EvidenceType.MALWARE_FAMILY,
                        "Malware family: TrickBot",
                        value="TrickBot",
                        sources=("malwarebazaar",),
                    ),
                ),
                relationships=(
                    _rel(
                        RelationshipType.INDICATES,
                        RelationshipTargetType.MALWARE_FAMILY,
                        "TrickBot",
                        sources=("malwarebazaar",),
                    ),
                ),
            ),
            knowledge=_empty(EntityType.SHA256, _hash),
            posture=S.HIGH,
            overall_band=B.HIGH,  # 0.35*0.7 + 0.25 + 0 + 0.15 = 0.645
            findings=(EF(FC.MALWARE, S.HIGH, B.HIGH, min_recommendations=2),),
            rollup=(RA.BLOCK, RA.INVESTIGATE),
        )
    )
    add(
        Scenario(
            id="hash_malware_two_families",
            kind="Malware hash (corroborated)",
            description="Two independent families corroborate the malware attribution.",
            entity=_entity(EntityType.SHA256, "b" * 64),
            ti=_agg(
                EntityType.SHA256,
                "b" * 64,
                providers=(
                    _prov("malwarebazaar", level=ReputationLevel.MALICIOUS, score=100),
                    _prov("otx", level=ReputationLevel.SUSPICIOUS, score=60),
                ),
                evidence=(
                    _ev(
                        EvidenceType.MALWARE_FAMILY,
                        "Malware family: TrickBot",
                        value="TrickBot",
                        sources=("malwarebazaar",),
                    ),
                    _ev(
                        EvidenceType.MALWARE_FAMILY,
                        "Malware family: TrickBot",
                        value="TrickBot",
                        sources=("otx",),
                    ),
                ),
            ),
            knowledge=_empty(EntityType.SHA256, "b" * 64),
            posture=S.HIGH,
            overall_band=B.HIGH,
            findings=(EF(FC.MALWARE, S.HIGH, B.HIGH),),
        )
    )
    add(
        Scenario(
            id="hash_echo_chamber",
            kind="Echo-chamber corroboration",
            description="URLhaus + MalwareBazaar share the abuse.ch family → no corroboration.",
            entity=_entity(EntityType.SHA256, "c" * 64),
            ti=_agg(
                EntityType.SHA256,
                "c" * 64,
                providers=(
                    _prov("urlhaus", level=ReputationLevel.MALICIOUS, score=100),
                    _prov("malwarebazaar", level=ReputationLevel.MALICIOUS, score=100),
                ),
                evidence=(
                    _ev(
                        EvidenceType.MALWARE_FAMILY,
                        "Malware family: Qakbot",
                        value="Qakbot",
                        sources=("urlhaus",),
                    ),
                    _ev(
                        EvidenceType.MALWARE_FAMILY,
                        "Malware family: Qakbot",
                        value="Qakbot",
                        sources=("malwarebazaar",),
                    ),
                ),
            ),
            knowledge=_empty(EntityType.SHA256, "c" * 64),
            posture=S.HIGH,
            overall_band=B.HIGH,  # one family → corroboration 0 (echo-chamber guard)
            findings=(EF(FC.MALWARE, S.HIGH, B.HIGH),),
        )
    )
    add(
        Scenario(
            id="hash_unknown",
            kind="Unknown hash",
            description="Every provider returns not-found → no evidence, no finding.",
            entity=_entity(EntityType.SHA256, "d" * 64),
            ti=_agg(
                EntityType.SHA256,
                "d" * 64,
                providers=(
                    _prov("malwarebazaar", status=ResultStatus.NOT_FOUND),
                    _prov("otx", status=ResultStatus.NOT_FOUND),
                ),
            ),
            knowledge=_empty(EntityType.SHA256, "d" * 64),
            posture=S.INFORMATIONAL,
            overall_band=B.INSUFFICIENT,
        )
    )
    add(
        Scenario(
            id="hash_sandbox_no_family",
            kind="Sandbox observation, no family",
            description="A sandbox observation without a family triggers no rule.",
            entity=_entity(EntityType.SHA256, "e" * 64),
            ti=_agg(
                EntityType.SHA256,
                "e" * 64,
                providers=(_prov("cape"),),
                evidence=(
                    _ev(
                        EvidenceType.SANDBOX_OBSERVATION,
                        "Writes to startup folder",
                        value="persistence",
                        sources=("cape",),
                        observed_at=RECENT,
                    ),
                ),
            ),
            knowledge=_empty(EntityType.SHA256, "e" * 64),
            posture=S.INFORMATIONAL,
            overall_band=B.MODERATE,  # fallback echoes evidence strength though no finding fired
        )
    )
    add(
        Scenario(
            id="hash_malware_via_relationship",
            kind="Malware via relationship only",
            description="An INDICATES-malware relationship alone is enough for a malware finding.",
            entity=_entity(EntityType.SHA256, "f" * 64),
            ti=_agg(
                EntityType.SHA256,
                "f" * 64,
                providers=(_prov("otx", level=ReputationLevel.SUSPICIOUS, score=50),),
                relationships=(
                    _rel(
                        RelationshipType.INDICATES,
                        RelationshipTargetType.MALWARE_FAMILY,
                        "AgentTesla",
                        sources=("otx",),
                    ),
                ),
            ),
            knowledge=_empty(EntityType.SHA256, "f" * 64),
            posture=S.HIGH,
            overall_band=B.HIGH,
            findings=(EF(FC.MALWARE, S.HIGH, B.HIGH),),
        )
    )

    # ===================================================================== #
    # CVE (nvd 0.95 nist) — knowledge only
    # ===================================================================== #

    def _cve_knowledge(cve: str, severity_label: str, cwe: str = "CWE-79") -> AggregatedResult:
        return _agg(
            EntityType.CVE,
            cve,
            providers=(_prov("nvd"),),
            evidence=(
                _ev(EvidenceType.CLASSIFICATION, "Remote code execution in ...", sources=("nvd",)),
                _ev(
                    EvidenceType.CATEGORY,
                    f"Severity: {severity_label}",
                    value=severity_label,
                    sources=("nvd",),
                ),
                _ev(EvidenceType.CATEGORY, cwe, value=cwe, sources=("nvd",)),
                _ev(EvidenceType.OTHER, "CVSS 3.1 Base Score: 9.8", value="9.8", sources=("nvd",)),
                _ev(EvidenceType.FIRST_SEEN, "Published: 2021-12-10", sources=("nvd",)),
            ),
            relationships=(
                _rel(
                    RelationshipType.RELATED_TO,
                    RelationshipTargetType.WEAKNESS,
                    cwe,
                    sources=("nvd",),
                ),
            ),
        )

    add(
        Scenario(
            id="cve_critical",
            kind="Critical CVE",
            description="A CRITICAL NVD severity → critical vulnerability finding (HIGH_PRIORITY).",
            entity=_entity(EntityType.CVE, "CVE-2021-44228"),
            ti=_empty(EntityType.CVE, "CVE-2021-44228"),
            knowledge=_cve_knowledge("CVE-2021-44228", "CRITICAL"),
            posture=S.CRITICAL,
            overall_band=B.HIGH,  # single nist family → corroboration 0 → ~73
            findings=(
                EF(FC.VULNERABILITY, S.CRITICAL, B.HIGH, priority=10, min_recommendations=2),
            ),
            rollup=(RA.PATCH_IMMEDIATELY, RA.INVESTIGATE),
        )
    )
    add(
        Scenario(
            id="cve_high",
            kind="High CVE",
            description="A HIGH NVD severity → high vulnerability finding.",
            entity=_entity(EntityType.CVE, "CVE-2023-1111"),
            ti=_empty(EntityType.CVE, "CVE-2023-1111"),
            knowledge=_cve_knowledge("CVE-2023-1111", "HIGH"),
            posture=S.HIGH,
            overall_band=B.HIGH,
            findings=(EF(FC.VULNERABILITY, S.HIGH, B.HIGH, priority=110),),
            rollup=(RA.PATCH_IMMEDIATELY, RA.INVESTIGATE),
        )
    )
    add(
        Scenario(
            id="cve_medium",
            kind="Medium CVE",
            description="A MEDIUM NVD severity falls below the vulnerability rule → no finding.",
            entity=_entity(EntityType.CVE, "CVE-2023-2222"),
            ti=_empty(EntityType.CVE, "CVE-2023-2222"),
            knowledge=_cve_knowledge("CVE-2023-2222", "MEDIUM"),
            posture=S.INFORMATIONAL,
            overall_band=B.INSUFFICIENT,
        )
    )
    add(
        Scenario(
            id="cve_low",
            kind="Low severity CVE",
            description="A LOW NVD severity yields no finding (no exploit/reputation signal).",
            entity=_entity(EntityType.CVE, "CVE-2023-3333"),
            ti=_empty(EntityType.CVE, "CVE-2023-3333"),
            knowledge=_cve_knowledge("CVE-2023-3333", "LOW"),
            posture=S.INFORMATIONAL,
            overall_band=B.INSUFFICIENT,
        )
    )
    add(
        Scenario(
            id="cve_critical_prod_ctx",
            kind="Critical CVE on critical production asset",
            description="Context boost (80) clamps the already-urgent critical CVE priority to 0.",
            entity=_entity(EntityType.CVE, "CVE-2021-44228"),
            ti=_empty(EntityType.CVE, "CVE-2021-44228"),
            knowledge=_cve_knowledge("CVE-2021-44228", "CRITICAL"),
            posture=S.CRITICAL,
            overall_band=B.HIGH,
            findings=(EF(FC.VULNERABILITY, S.CRITICAL, B.HIGH, priority=0),),
            rollup=(RA.PATCH_IMMEDIATELY, RA.INVESTIGATE),
            context=InvestigationContext(
                criticality=AssetCriticality.CRITICAL,
                environment=Environment.PRODUCTION,
                internet_facing=True,
            ),
        )
    )
    add(
        Scenario(
            id="cve_high_prod_ctx",
            kind="High CVE on production asset",
            description="Production + internet (boost 40) shifts a high CVE priority 110 → 70.",
            entity=_entity(EntityType.CVE, "CVE-2023-1111"),
            ti=_empty(EntityType.CVE, "CVE-2023-1111"),
            knowledge=_cve_knowledge("CVE-2023-1111", "HIGH"),
            posture=S.HIGH,
            overall_band=B.HIGH,
            findings=(EF(FC.VULNERABILITY, S.HIGH, B.HIGH, priority=70),),
            context=InvestigationContext(environment=Environment.PRODUCTION, internet_facing=True),
        )
    )

    # ===================================================================== #
    # MITRE ATT&CK technique / actor / software (mitre_attack 0.90 mitre)
    # ===================================================================== #

    def _technique_knowledge(tid: str) -> AggregatedResult:
        return _agg(
            EntityType.MITRE_TECHNIQUE,
            tid,
            providers=(_prov("mitre_attack"),),
            evidence=(
                _ev(
                    EvidenceType.CLASSIFICATION,
                    "Command and Scripting Interpreter",
                    value=tid,
                    sources=("mitre_attack",),
                ),
                _ev(
                    EvidenceType.CATEGORY,
                    "Tactic: execution",
                    value="execution",
                    sources=("mitre_attack",),
                ),
                _ev(EvidenceType.DETECTION, "Monitor process execution", sources=("mitre_attack",)),
            ),
            relationships=(
                _rel(
                    RelationshipType.RELATED_TO,
                    RelationshipTargetType.ATTACK_PATTERN,
                    f"{tid}.001",
                    sources=("mitre_attack",),
                ),
            ),
        )

    add(
        Scenario(
            id="technique_t1059",
            kind="ATT&CK technique",
            description="A MITRE technique → an attack-pattern finding (MEDIUM).",
            entity=_entity(EntityType.MITRE_TECHNIQUE, "T1059"),
            ti=_empty(EntityType.MITRE_TECHNIQUE, "T1059"),
            knowledge=_technique_knowledge("T1059"),
            posture=S.MEDIUM,
            overall_band=B.HIGH,  # single mitre family → ~72
            findings=(
                EF(FC.ATTACK_PATTERN, S.MEDIUM, B.HIGH, priority=210, min_recommendations=2),
            ),
            rollup=(RA.THREAT_HUNT, RA.GENERATE_DETECTION),
        )
    )
    add(
        Scenario(
            id="technique_subtechnique",
            kind="ATT&CK sub-technique",
            description="A sub-technique behaves identically to a technique.",
            entity=_entity(EntityType.MITRE_TECHNIQUE, "T1059.001"),
            ti=_empty(EntityType.MITRE_TECHNIQUE, "T1059.001"),
            knowledge=_technique_knowledge("T1059.001"),
            posture=S.MEDIUM,
            overall_band=B.HIGH,
            findings=(EF(FC.ATTACK_PATTERN, S.MEDIUM, B.HIGH),),
        )
    )
    add(
        Scenario(
            id="technique_critical_ctx",
            kind="Technique on critical production asset",
            description="Context boost (80) shifts a medium technique finding 210 → 130.",
            entity=_entity(EntityType.MITRE_TECHNIQUE, "T1059"),
            ti=_empty(EntityType.MITRE_TECHNIQUE, "T1059"),
            knowledge=_technique_knowledge("T1059"),
            posture=S.MEDIUM,
            overall_band=B.HIGH,
            findings=(EF(FC.ATTACK_PATTERN, S.MEDIUM, B.HIGH, priority=130),),
            context=InvestigationContext(
                criticality=AssetCriticality.CRITICAL,
                environment=Environment.PRODUCTION,
                internet_facing=True,
            ),
        )
    )
    add(
        Scenario(
            id="actor_apt28",
            kind="Threat actor",
            description="A MITRE group → a threat-actor finding plus its technique usage.",
            entity=_entity(EntityType.THREAT_ACTOR, "APT28"),
            ti=_empty(EntityType.THREAT_ACTOR, "APT28"),
            knowledge=_agg(
                EntityType.THREAT_ACTOR,
                "APT28",
                providers=(_prov("mitre_attack"),),
                evidence=(
                    _ev(
                        EvidenceType.CLASSIFICATION,
                        "APT28 is a Russian state-sponsored group",
                        value="G0007",
                        sources=("mitre_attack",),
                    ),
                    _ev(
                        EvidenceType.TAG,
                        "Alias: Fancy Bear",
                        value="Fancy Bear",
                        sources=("mitre_attack",),
                    ),
                ),
                relationships=(
                    _rel(
                        RelationshipType.USES,
                        RelationshipTargetType.ATTACK_PATTERN,
                        "T1566",
                        sources=("mitre_attack",),
                    ),
                ),
            ),
            posture=S.MEDIUM,
            overall_band=B.HIGH,
            findings=(
                EF(FC.THREAT_ACTOR, S.MEDIUM, B.HIGH),
                EF(FC.ATTACK_PATTERN, S.MEDIUM, B.HIGH),
            ),
            rollup=(RA.INVESTIGATE, RA.THREAT_HUNT, RA.ENRICH, RA.GENERATE_DETECTION),
        )
    )
    add(
        Scenario(
            id="actor_attributed_on_hash",
            kind="Actor attribution on a hash",
            description="An ATTRIBUTED_TO actor relationship yields a threat-actor finding.",
            entity=_entity(EntityType.SHA256, "1" * 64),
            ti=_agg(
                EntityType.SHA256,
                "1" * 64,
                providers=(_prov("otx", level=ReputationLevel.SUSPICIOUS, score=50),),
                relationships=(
                    _rel(
                        RelationshipType.ATTRIBUTED_TO,
                        RelationshipTargetType.THREAT_ACTOR,
                        "Lazarus",
                        sources=("otx",),
                    ),
                ),
            ),
            knowledge=_empty(EntityType.SHA256, "1" * 64),
            posture=S.MEDIUM,
            overall_band=B.HIGH,
            findings=(EF(FC.THREAT_ACTOR, S.MEDIUM, B.HIGH),),
        )
    )

    add(
        Scenario(
            id="malware_emotet",
            kind="Malware family",
            description="A MITRE software entry → a malware finding plus its technique usage.",
            entity=_entity(EntityType.MALWARE_FAMILY, "Emotet"),
            ti=_empty(EntityType.MALWARE_FAMILY, "Emotet"),
            knowledge=_agg(
                EntityType.MALWARE_FAMILY,
                "Emotet",
                providers=(_prov("mitre_attack"),),
                evidence=(
                    _ev(
                        EvidenceType.CLASSIFICATION,
                        "Emotet is a modular banking trojan",
                        value="S0367",
                        sources=("mitre_attack",),
                    ),
                    _ev(EvidenceType.TAG, "Alias: Geodo", value="Geodo", sources=("mitre_attack",)),
                ),
                relationships=(
                    _rel(
                        RelationshipType.USES,
                        RelationshipTargetType.ATTACK_PATTERN,
                        "T1059",
                        sources=("mitre_attack",),
                    ),
                ),
            ),
            posture=S.HIGH,
            overall_band=B.HIGH,
            findings=(
                EF(FC.MALWARE, S.HIGH, B.HIGH),
                EF(FC.ATTACK_PATTERN, S.MEDIUM, B.HIGH),
            ),
            rollup=(RA.BLOCK, RA.INVESTIGATE, RA.THREAT_HUNT, RA.GENERATE_DETECTION),
        )
    )
    add(
        Scenario(
            id="malware_very_high",
            kind="Very-high confidence malware",
            description="Three independent families (abuse.ch + OTX + MITRE) → VERY_HIGH.",
            entity=_entity(EntityType.MALWARE_FAMILY, "Emotet"),
            ti=_agg(
                EntityType.MALWARE_FAMILY,
                "Emotet",
                providers=(
                    _prov("urlhaus", level=ReputationLevel.MALICIOUS, score=100),
                    _prov("otx", level=ReputationLevel.SUSPICIOUS, score=70),
                ),
                evidence=(
                    _ev(
                        EvidenceType.MALWARE_FAMILY,
                        "Malware family: Emotet",
                        value="Emotet",
                        sources=("urlhaus",),
                    ),
                    _ev(
                        EvidenceType.MALWARE_FAMILY,
                        "Malware family: Emotet",
                        value="Emotet",
                        sources=("otx",),
                    ),
                ),
            ),
            knowledge=_agg(
                EntityType.MALWARE_FAMILY,
                "Emotet",
                providers=(_prov("mitre_attack"),),
                evidence=(
                    _ev(
                        EvidenceType.CLASSIFICATION,
                        "Emotet is a modular banking trojan",
                        value="S0367",
                        sources=("mitre_attack",),
                    ),
                ),
            ),
            posture=S.HIGH,
            overall_band=B.VERY_HIGH,  # 3 families, authority 0.9 → ~88
            findings=(EF(FC.MALWARE, S.HIGH, B.VERY_HIGH, priority=100, min_recommendations=2),),
            rollup=(RA.BLOCK, RA.INVESTIGATE),
        )
    )

    # ===================================================================== #
    # CWE / CAPEC (cwe 0.90 mitre · capec 0.85 mitre) — knowledge only
    # ===================================================================== #

    add(
        Scenario(
            id="cwe_79",
            kind="CWE weakness",
            description="A CWE related to attack patterns yields an attack-pattern finding.",
            entity=_entity(EntityType.CWE, "CWE-79"),
            ti=_empty(EntityType.CWE, "CWE-79"),
            knowledge=_agg(
                EntityType.CWE,
                "CWE-79",
                providers=(_prov("cwe"),),
                evidence=(
                    _ev(
                        EvidenceType.CLASSIFICATION,
                        "Improper Neutralization of Input (XSS)",
                        value="CWE-79",
                        sources=("cwe",),
                    ),
                    _ev(EvidenceType.CATEGORY, "Abstraction: Base", value="Base", sources=("cwe",)),
                ),
                relationships=(
                    _rel(
                        RelationshipType.RELATED_TO,
                        RelationshipTargetType.WEAKNESS,
                        "CWE-80",
                        sources=("cwe",),
                    ),
                    _rel(
                        RelationshipType.RELATED_TO,
                        RelationshipTargetType.ATTACK_PATTERN,
                        "CAPEC-63",
                        sources=("cwe",),
                    ),
                ),
            ),
            posture=S.MEDIUM,
            overall_band=B.HIGH,
            findings=(EF(FC.ATTACK_PATTERN, S.MEDIUM, B.HIGH),),
        )
    )
    add(
        Scenario(
            id="capec_242",
            kind="CAPEC attack pattern",
            description="A CAPEC pattern related to ATT&CK techniques → attack-pattern finding.",
            entity=_entity(EntityType.CAPEC, "CAPEC-242"),
            ti=_empty(EntityType.CAPEC, "CAPEC-242"),
            knowledge=_agg(
                EntityType.CAPEC,
                "CAPEC-242",
                providers=(_prov("capec"),),
                evidence=(
                    _ev(
                        EvidenceType.CLASSIFICATION,
                        "Code Injection",
                        value="CAPEC-242",
                        sources=("capec",),
                    ),
                    _ev(
                        EvidenceType.CATEGORY, "Likelihood: High", value="High", sources=("capec",)
                    ),
                    _ev(
                        EvidenceType.DETECTION,
                        "Monitor for anomalous code execution",
                        sources=("capec",),
                    ),
                ),
                relationships=(
                    _rel(
                        RelationshipType.EXPLOITS,
                        RelationshipTargetType.WEAKNESS,
                        "CWE-94",
                        sources=("capec",),
                    ),
                    _rel(
                        RelationshipType.RELATED_TO,
                        RelationshipTargetType.ATTACK_PATTERN,
                        "T1059",
                        sources=("capec",),
                    ),
                ),
            ),
            posture=S.MEDIUM,
            overall_band=B.HIGH,  # capec authority 0.85 → ~70
            findings=(EF(FC.ATTACK_PATTERN, S.MEDIUM, B.HIGH),),
        )
    )

    # ===================================================================== #
    # Cross-framework & multi-finding
    # ===================================================================== #

    add(
        Scenario(
            id="ip_malware_actor_technique",
            kind="Multiple findings (IPv4)",
            description="A malicious IP that drops malware, is attributed, and uses a technique.",
            entity=_entity(EntityType.IPV4, "185.220.101.1"),
            ti=_agg(
                EntityType.IPV4,
                "185.220.101.1",
                providers=(_prov("abuseipdb", level=ReputationLevel.MALICIOUS, score=100),),
                relationships=(
                    _rel(
                        RelationshipType.INDICATES,
                        RelationshipTargetType.MALWARE_FAMILY,
                        "Cobalt Strike",
                        sources=("otx",),
                    ),
                    _rel(
                        RelationshipType.ATTRIBUTED_TO,
                        RelationshipTargetType.THREAT_ACTOR,
                        "APT29",
                        sources=("otx",),
                    ),
                    _rel(
                        RelationshipType.USES,
                        RelationshipTargetType.ATTACK_PATTERN,
                        "T1071",
                        sources=("otx",),
                    ),
                ),
            ),
            knowledge=_empty(EntityType.IPV4, "185.220.101.1"),
            posture=S.HIGH,
            overall_band=B.HIGH,
            findings=(
                EF(FC.MALICIOUS_INFRASTRUCTURE, S.HIGH, B.HIGH),
                EF(FC.MALWARE, S.HIGH, B.HIGH),
                EF(FC.THREAT_ACTOR, S.MEDIUM, B.HIGH),
                EF(FC.ATTACK_PATTERN, S.MEDIUM, B.HIGH),
            ),
        )
    )
    add(
        Scenario(
            id="multi_finding_context_shift",
            kind="Context shifts a queue uniformly",
            description="Context lowers every priority by the same boost; order is preserved.",
            entity=_entity(EntityType.IPV4, "185.220.101.2"),
            ti=_agg(
                EntityType.IPV4,
                "185.220.101.2",
                providers=(_prov("abuseipdb", level=ReputationLevel.MALICIOUS, score=100),),
                relationships=(
                    _rel(
                        RelationshipType.INDICATES,
                        RelationshipTargetType.MALWARE_FAMILY,
                        "Cobalt Strike",
                        sources=("otx",),
                    ),
                    _rel(
                        RelationshipType.USES,
                        RelationshipTargetType.ATTACK_PATTERN,
                        "T1071",
                        sources=("otx",),
                    ),
                ),
            ),
            knowledge=_empty(EntityType.IPV4, "185.220.101.2"),
            posture=S.HIGH,
            overall_band=B.HIGH,
            findings=(
                # infra/malware HIGH (base 100, band HIGH penalty 10, boost 80) → 30
                EF(FC.MALICIOUS_INFRASTRUCTURE, S.HIGH, B.HIGH, priority=30),
                EF(FC.MALWARE, S.HIGH, B.HIGH, priority=30),
                # technique MEDIUM (base 200, band HIGH penalty 10, boost 80) → 130
                EF(FC.ATTACK_PATTERN, S.MEDIUM, B.HIGH, priority=130),
            ),
            context=InvestigationContext(
                criticality=AssetCriticality.CRITICAL,
                environment=Environment.PRODUCTION,
                internet_facing=True,
            ),
        )
    )

    # ===================================================================== #
    # Additional coverage: reputation levels, hash subtypes, corroboration
    # ===================================================================== #

    add(
        Scenario(
            id="ip_likely_malicious",
            kind="Likely-malicious IPv4",
            description="A likely-malicious verdict is still supporting → a finding.",
            entity=_entity(EntityType.IPV4, "77.77.77.77"),
            ti=_agg(
                EntityType.IPV4,
                "77.77.77.77",
                providers=(_prov("abuseipdb", level=ReputationLevel.LIKELY_MALICIOUS, score=75),),
            ),
            knowledge=_empty(EntityType.IPV4, "77.77.77.77"),
            posture=S.HIGH,
            overall_band=B.HIGH,
            findings=(EF(FC.MALICIOUS_INFRASTRUCTURE, S.HIGH, B.HIGH, priority=110),),
        )
    )
    add(
        Scenario(
            id="ip_three_independent_sources",
            kind="Three independent sources (IPv4)",
            description="Three families corroborate but community TI still caps at HIGH.",
            entity=_entity(EntityType.IPV4, "78.78.78.78"),
            ti=_agg(
                EntityType.IPV4,
                "78.78.78.78",
                providers=(
                    _prov("abuseipdb", level=ReputationLevel.MALICIOUS, score=100),
                    _prov("otx", level=ReputationLevel.SUSPICIOUS, score=60),
                    _prov("greynoise", level=ReputationLevel.MALICIOUS, score=90),
                ),
            ),
            knowledge=_empty(EntityType.IPV4, "78.78.78.78"),
            posture=S.HIGH,
            overall_band=B.HIGH,  # 3 families, authority 0.6 → ~78, still HIGH
            findings=(EF(FC.MALICIOUS_INFRASTRUCTURE, S.HIGH, B.HIGH),),
        )
    )
    add(
        Scenario(
            id="domain_malicious_otx",
            kind="Malicious domain",
            description="A suspicious OTX domain → a malicious-infrastructure finding.",
            entity=_entity(
                EntityType.DOMAIN,
                "dga-7f3a.example",
            ),
            ti=_agg(
                EntityType.DOMAIN,
                "dga-7f3a.example",
                providers=(_prov("otx", level=ReputationLevel.SUSPICIOUS, score=55),),
            ),
            knowledge=_empty(EntityType.DOMAIN, "dga-7f3a.example"),
            posture=S.HIGH,
            overall_band=B.HIGH,
            findings=(EF(FC.MALICIOUS_INFRASTRUCTURE, S.HIGH, B.HIGH),),
        )
    )
    add(
        Scenario(
            id="url_benign",
            kind="Benign URL",
            description="A benign URL verdict yields no finding.",
            entity=_entity(EntityType.URL, "https://good.example/home"),
            ti=_agg(
                EntityType.URL,
                "https://good.example/home",
                providers=(_prov("urlscan", level=ReputationLevel.BENIGN, score=0),),
            ),
            knowledge=_empty(EntityType.URL, "https://good.example/home"),
            posture=S.INFORMATIONAL,
            overall_band=B.INSUFFICIENT,
            overall_contested=True,
        )
    )
    add(
        Scenario(
            id="md5_malware",
            kind="Malware hash (MD5)",
            description="An MD5 malware hash behaves identically to SHA256.",
            entity=_entity(EntityType.MD5, "0" * 32),
            ti=_agg(
                EntityType.MD5,
                "0" * 32,
                providers=(_prov("malwarebazaar", level=ReputationLevel.MALICIOUS, score=100),),
                evidence=(
                    _ev(
                        EvidenceType.MALWARE_FAMILY,
                        "Malware family: Formbook",
                        value="Formbook",
                        sources=("malwarebazaar",),
                    ),
                ),
            ),
            knowledge=_empty(EntityType.MD5, "0" * 32),
            posture=S.HIGH,
            overall_band=B.HIGH,
            findings=(EF(FC.MALWARE, S.HIGH, B.HIGH),),
        )
    )
    add(
        Scenario(
            id="sha1_malware",
            kind="Malware hash (SHA1)",
            description="A SHA1 malware hash behaves identically to SHA256.",
            entity=_entity(EntityType.SHA1, "2" * 40),
            ti=_agg(
                EntityType.SHA1,
                "2" * 40,
                providers=(_prov("malwarebazaar", level=ReputationLevel.MALICIOUS, score=100),),
                evidence=(
                    _ev(
                        EvidenceType.MALWARE_FAMILY,
                        "Malware family: RedLine",
                        value="RedLine",
                        sources=("malwarebazaar",),
                    ),
                ),
            ),
            knowledge=_empty(EntityType.SHA1, "2" * 40),
            posture=S.HIGH,
            overall_band=B.HIGH,
            findings=(EF(FC.MALWARE, S.HIGH, B.HIGH),),
        )
    )
    add(
        Scenario(
            id="hash_malware_stale_family",
            kind="Stale malware attribution",
            description="A stale family observation (no fresh corroboration) decays to MODERATE.",
            entity=_entity(EntityType.SHA256, "3" * 64),
            ti=_agg(
                EntityType.SHA256,
                "3" * 64,
                providers=(_prov("malwarebazaar", level=ReputationLevel.MALICIOUS, score=100),),
                evidence=(
                    _ev(
                        EvidenceType.MALWARE_FAMILY,
                        "Malware family: Dridex",
                        value="Dridex",
                        sources=("malwarebazaar",),
                        observed_at=STALE,
                    ),
                ),
            ),
            knowledge=_empty(EntityType.SHA256, "3" * 64),
            posture=S.HIGH,
            overall_band=B.MODERATE,  # freshness floor on the only supporting item
            findings=(EF(FC.MALWARE, S.HIGH, B.MODERATE, min_recommendations=2),),
            rollup=(RA.BLOCK, RA.INVESTIGATE),
        )
    )
    add(
        Scenario(
            id="cve_critical_corroborated",
            kind="Critical CVE corroborated by TI",
            description="An NVD critical CVE also seen in OTX (two families) reaches VERY_HIGH.",
            entity=_entity(EntityType.CVE, "CVE-2021-44228"),
            ti=_agg(
                EntityType.CVE,
                "CVE-2021-44228",
                providers=(_prov("otx", level=ReputationLevel.SUSPICIOUS, score=60),),
                evidence=(
                    _ev(
                        EvidenceType.PULSE_MATCH,
                        "OTX pulse: Log4Shell exploitation",
                        value="log4shell",
                        sources=("otx",),
                        observed_at=RECENT,
                    ),
                ),
            ),
            knowledge=_cve_knowledge("CVE-2021-44228", "CRITICAL"),
            posture=S.CRITICAL,
            overall_band=B.VERY_HIGH,  # nist + otx families, authority 0.95 → ~86
            findings=(EF(FC.VULNERABILITY, S.CRITICAL, B.VERY_HIGH, priority=0),),
            rollup=(RA.PATCH_IMMEDIATELY, RA.INVESTIGATE),
        )
    )
    add(
        Scenario(
            id="cve_high_critical_asset_only",
            kind="High CVE on a high-criticality asset",
            description="Criticality HIGH alone (boost 25) shifts a high CVE priority 110 → 85.",
            entity=_entity(EntityType.CVE, "CVE-2023-1111"),
            ti=_empty(EntityType.CVE, "CVE-2023-1111"),
            knowledge=_cve_knowledge("CVE-2023-1111", "HIGH"),
            posture=S.HIGH,
            overall_band=B.HIGH,
            findings=(EF(FC.VULNERABILITY, S.HIGH, B.HIGH, priority=85),),
            context=InvestigationContext(criticality=AssetCriticality.HIGH),
        )
    )
    add(
        Scenario(
            id="actor_single_finding",
            kind="Threat actor (no technique links)",
            description="A threat actor with only a campaign association → a single actor finding.",
            entity=_entity(EntityType.THREAT_ACTOR, "Sandworm"),
            ti=_empty(EntityType.THREAT_ACTOR, "Sandworm"),
            knowledge=_agg(
                EntityType.THREAT_ACTOR,
                "Sandworm",
                providers=(_prov("mitre_attack"),),
                evidence=(
                    _ev(
                        EvidenceType.CLASSIFICATION,
                        "Sandworm Team",
                        value="G0034",
                        sources=("mitre_attack",),
                    ),
                    _ev(
                        EvidenceType.TAG,
                        "Alias: Voodoo Bear",
                        value="Voodoo Bear",
                        sources=("mitre_attack",),
                    ),
                ),
                relationships=(
                    _rel(
                        RelationshipType.ASSOCIATED_WITH,
                        RelationshipTargetType.CAMPAIGN,
                        "NotPetya",
                        sources=("mitre_attack",),
                    ),
                ),
            ),
            posture=S.MEDIUM,
            overall_band=B.HIGH,
            findings=(EF(FC.THREAT_ACTOR, S.MEDIUM, B.HIGH, priority=210, min_recommendations=2),),
            rollup=(RA.INVESTIGATE, RA.ENRICH),
        )
    )
    add(
        Scenario(
            id="ip_malicious_staging_ctx",
            kind="Context: staging environment",
            description="Staging (boost 10) shifts a malicious-infra priority 110 → 100.",
            entity=_entity(EntityType.IPV4, "45.155.205.233"),
            ti=_ip_ctx_ti,
            knowledge=_empty(EntityType.IPV4, "45.155.205.233"),
            posture=S.HIGH,
            overall_band=B.HIGH,
            findings=(EF(FC.MALICIOUS_INFRASTRUCTURE, S.HIGH, B.HIGH, priority=100),),
            context=InvestigationContext(environment=Environment.STAGING),
        )
    )
    add(
        Scenario(
            id="ip_malicious_dev_ctx_noop",
            kind="Context: development (no boost)",
            description="Development + unknown criticality add no boost — priority stays 110.",
            entity=_entity(EntityType.IPV4, "45.155.205.233"),
            ti=_ip_ctx_ti,
            knowledge=_empty(EntityType.IPV4, "45.155.205.233"),
            posture=S.HIGH,
            overall_band=B.HIGH,
            findings=(EF(FC.MALICIOUS_INFRASTRUCTURE, S.HIGH, B.HIGH, priority=110),),
            context=InvestigationContext(environment=Environment.DEVELOPMENT),
        )
    )

    # ===================================================================== #
    # Fall-through / empty
    # ===================================================================== #

    add(
        Scenario(
            id="freetext_empty",
            kind="No findings (freetext)",
            description="Unresolvable freetext with no provider data → no findings.",
            entity=_entity(EntityType.FREETEXT, "lorem ipsum"),
            ti=_empty(EntityType.FREETEXT, "lorem ipsum"),
            knowledge=_empty(EntityType.FREETEXT, "lorem ipsum"),
            posture=S.INFORMATIONAL,
            overall_band=B.INSUFFICIENT,
        )
    )
    add(
        Scenario(
            id="unknown_empty",
            kind="No findings (unknown)",
            description="An unknown entity with no data → no findings.",
            entity=_entity(EntityType.UNKNOWN, "???"),
            ti=_empty(EntityType.UNKNOWN, "???"),
            knowledge=_empty(EntityType.UNKNOWN, "???"),
            posture=S.INFORMATIONAL,
            overall_band=B.INSUFFICIENT,
        )
    )
    add(
        Scenario(
            id="ip_tags_only",
            kind="Tag-only evidence",
            description="Tag evidence is contextual, not supporting → no finding.",
            entity=_entity(EntityType.IPV4, "203.0.113.7"),
            ti=_agg(
                EntityType.IPV4,
                "203.0.113.7",
                providers=(_prov("otx"),),
                evidence=(
                    _ev(EvidenceType.TAG, "Tag: scanner", value="scanner", sources=("otx",)),
                ),
            ),
            knowledge=_empty(EntityType.IPV4, "203.0.113.7"),
            posture=S.INFORMATIONAL,
            overall_band=B.INSUFFICIENT,
        )
    )

    return tuple(scenarios)


SCENARIOS: tuple[Scenario, ...] = _build()


# Quick guard against accidental id collisions (which would mask a scenario).
_seen: set[str] = set()
for _s in SCENARIOS:
    if _s.id in _seen:
        raise ValueError(f"duplicate benchmark scenario id: {_s.id}")
    _seen.add(_s.id)
del _seen
