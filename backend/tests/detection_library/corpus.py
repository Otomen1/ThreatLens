"""Shared, deterministic fixtures for the Detection Knowledge Library tests.

A fixed ``NOW`` and a stable library built from the bundled seed keep every test
(and the golden snapshot) byte-reproducible and fully offline — no network, no
live GitHub, no clock.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from threatlens.detection_library import (
    DetectionLibrary,
    build_default_provider_registry,
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

NOW = datetime(2024, 6, 1, tzinfo=UTC)

# Concrete IOCs the seed corpus was authored around (drive EXACT matches).
IP = "45.155.205.233"
DOMAIN = "malware-c2.example.net"
SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

# The stable library under test (bundled offline seed).
LIBRARY = DetectionLibrary(build_default_provider_registry().all_rules())


def _conf(score: int = 80) -> Confidence:
    band = ConfidenceBand.HIGH if score >= 65 else ConfidenceBand.MODERATE
    return Confidence(score=score, band=band)


def _rel(target_type: RelationshipTargetType, value: str) -> AttributedRelationship:
    verb = (
        RelationshipType.USES
        if target_type is RelationshipTargetType.ATTACK_PATTERN
        else RelationshipType.ASSOCIATED_WITH
    )
    return AttributedRelationship(
        relationship=Relationship(relationship=verb, target_type=target_type, target_value=value),
        sources=["mitre_attack"],
    )


def finding(
    fid: str,
    stype: EntityType,
    value: str,
    *,
    cats: tuple[FindingCategory, ...] = (FindingCategory.MALICIOUS_INFRASTRUCTURE,),
    techniques: tuple[str, ...] = (),
    malware: tuple[str, ...] = (),
    actors: tuple[str, ...] = (),
    severity: Severity = Severity.HIGH,
) -> Finding:
    rels = [_rel(RelationshipTargetType.ATTACK_PATTERN, t) for t in techniques]
    rels += [_rel(RelationshipTargetType.MALWARE_FAMILY, m) for m in malware]
    rels += [_rel(RelationshipTargetType.THREAT_ACTOR, a) for a in actors]
    return Finding(
        id=fid,
        title=f"{stype.value}:{value}",
        categories=frozenset(cats),
        subject_type=stype,
        subject_value=value,
        severity=severity,
        confidence=_conf(),
        sources=["abuseipdb"],
        relationships=rels,
    )


def summary(
    entity_type: EntityType, entity_value: str, findings: list[Finding]
) -> InvestigationSummary:
    posture = max((f.severity for f in findings), default=Severity.INFORMATIONAL)
    cats = frozenset(c for f in findings for c in f.categories)
    return InvestigationSummary(
        entity_type=entity_type,
        entity_value=entity_value,
        posture=posture,
        overall_confidence=_conf(),
        categories=cats,
        findings=findings,
        engine_version="1.0",
        generated_at=NOW,
    )


@dataclass(frozen=True)
class Scenario:
    id: str
    summary: InvestigationSummary


_MAL = FindingCategory.MALWARE


def _scenarios() -> list[Scenario]:
    out: list[Scenario] = []

    out.append(
        Scenario(
            "ip_c2",
            summary(
                EntityType.IPV4,
                IP,
                [
                    finding(
                        "f_ip", EntityType.IPV4, IP, techniques=("T1071",), malware=("GenericC2",)
                    ),
                ],
            ),
        )
    )
    out.append(
        Scenario(
            "domain_c2",
            summary(
                EntityType.DOMAIN,
                DOMAIN,
                [
                    finding("f_dom", EntityType.DOMAIN, DOMAIN, techniques=("T1071.001",)),
                ],
            ),
        )
    )
    out.append(
        Scenario(
            "hash_payload",
            summary(
                EntityType.SHA256,
                SHA256,
                [
                    finding(
                        "f_h",
                        EntityType.SHA256,
                        SHA256,
                        cats=(_MAL,),
                        techniques=("T1204.002",),
                        actors=("APT29",),
                    ),
                ],
            ),
        )
    )
    out.append(
        Scenario(
            "powershell",
            summary(
                EntityType.POWERSHELL_COMMAND,
                "IEX(x)",
                [
                    finding(
                        "f_ps",
                        EntityType.POWERSHELL_COMMAND,
                        "IEX(x)",
                        cats=(_MAL,),
                        techniques=("T1059.001",),
                    ),
                ],
            ),
        )
    )
    out.append(
        Scenario(
            "multi_ioc",
            summary(
                EntityType.IPV4,
                IP,
                [
                    finding("f_ip", EntityType.IPV4, IP, techniques=("T1071",)),
                    finding(
                        "f_h", EntityType.SHA256, SHA256, cats=(_MAL,), techniques=("T1204.002",)
                    ),
                    finding(
                        "f_ps",
                        EntityType.POWERSHELL_COMMAND,
                        "IEX(x)",
                        cats=(_MAL,),
                        techniques=("T1059.001",),
                    ),
                ],
            ),
        )
    )
    out.append(
        Scenario(
            "actor_only",
            summary(
                EntityType.THREAT_ACTOR,
                "APT29",
                [
                    finding(
                        "f_act",
                        EntityType.THREAT_ACTOR,
                        "APT29",
                        cats=(FindingCategory.THREAT_ACTOR,),
                        actors=("APT29",),
                    ),
                ],
            ),
        )
    )
    out.append(Scenario("no_findings", summary(EntityType.IPV4, "8.8.8.8", [])))
    out.append(
        Scenario(
            "unmatched",
            summary(
                EntityType.IPV4,
                "203.0.113.77",
                [
                    finding("f_u", EntityType.IPV4, "203.0.113.77", techniques=("T1583",)),
                ],
            ),
        )
    )
    return out


SCENARIOS: list[Scenario] = _scenarios()
