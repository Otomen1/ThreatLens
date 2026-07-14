"""A curated scenario corpus for the Graph Engine's golden regression.

Covers every documented policy decision: finding-relationship edges,
vocabulary alignment across ``EntityType``/``RelationshipTargetType``,
correlation-observation hub nodes, direct correlation-relationship edges,
same-subject self-loop omission, defensive skip of an unresolvable
correlation relationship, cross-observation node sharing, severity
aggregation, and the "referenced but never a subject" no-severity rule.
"""

from __future__ import annotations

from dataclasses import dataclass

from threatlens.correlation.models import CorrelationRelationshipType, CorrelationSummary
from threatlens.entities.types import EntityType
from threatlens.providers.results import RelationshipTargetType
from threatlens.reasoning.models import FindingCategory, InvestigationSummary, Severity

from .factories import (
    correlation_evidence,
    correlation_relationship,
    correlation_summary,
    finding,
    observation,
    relationship,
    summary,
)


@dataclass(frozen=True)
class Scenario:
    id: str
    summary: InvestigationSummary | None
    correlation: CorrelationSummary | None = None


CORPUS: tuple[Scenario, ...] = (
    Scenario("empty_investigation", summary([])),
    Scenario(
        "finding_with_no_relationships",
        summary([finding("f1")]),
    ),
    Scenario(
        "single_relationship_edge",
        summary([finding("f1", relationships=[relationship()])]),
    ),
    Scenario(
        "duplicate_relationship_across_findings",
        summary(
            [
                finding("f1", relationships=[relationship()]),
                finding(
                    "f2",
                    categories=[FindingCategory.REPUTATION],
                    severity=Severity.CRITICAL,
                    relationships=[relationship()],
                ),
            ]
        ),
    ),
    Scenario(
        "shared_entity_vocabulary_alignment",
        # f1's relationship target (RelationshipTargetType.MALWARE_FAMILY,
        # "Emotet") and f2's own subject (EntityType.MALWARE_FAMILY, "Emotet")
        # share an identical string value in both closed vocabularies, so
        # they must collapse into one canonical node.
        summary(
            [
                finding("f1", relationships=[relationship()]),
                finding(
                    "f2",
                    categories=[FindingCategory.MALWARE],
                    subject_type=EntityType.MALWARE_FAMILY,
                    subject_value="Emotet",
                    severity=Severity.CRITICAL,
                ),
            ]
        ),
    ),
    Scenario(
        "distinct_target_vocabulary_not_merged",
        # RelationshipTargetType.VULNERABILITY has no EntityType counterpart
        # with the same string value (EntityType uses "cve"); it must remain
        # its own distinct node, never speculatively remapped.
        summary(
            [
                finding(
                    "f1",
                    relationships=[
                        relationship(
                            target_type=RelationshipTargetType.VULNERABILITY,
                            target_value="CVE-2024-9999",
                        )
                    ],
                )
            ]
        ),
    ),
    Scenario(
        "observation_single_entity_hub",
        # Both evidence citations share one subject (a same_subject-style
        # observation), so exactly one distinct entity is cited.
        summary([finding("f1"), finding("f2", categories=[FindingCategory.EXPOSURE])]),
        correlation_summary(
            [
                observation(
                    "cor_1",
                    evidence_items=[
                        correlation_evidence("f1"),
                        correlation_evidence("f2", matched_category=FindingCategory.EXPOSURE),
                    ],
                )
            ]
        ),
    ),
    Scenario(
        "observation_two_entities_with_relationship",
        summary(
            [
                finding("f1", categories=[FindingCategory.MALWARE]),
                finding(
                    "f2",
                    categories=[FindingCategory.ATTACK_PATTERN],
                    subject_type=EntityType.MITRE_TECHNIQUE,
                    subject_value="T1059",
                ),
            ]
        ),
        correlation_summary(
            [
                observation(
                    "cor_2",
                    evidence_items=[
                        correlation_evidence("f1", matched_category=FindingCategory.MALWARE),
                        correlation_evidence(
                            "f2",
                            matched_category=FindingCategory.ATTACK_PATTERN,
                            subject_type=EntityType.MITRE_TECHNIQUE,
                            subject_value="T1059",
                        ),
                    ],
                    relationships=[
                        correlation_relationship(
                            source_finding_id="f1",
                            target_finding_id="f2",
                            rel_type=CorrelationRelationshipType.MAPPED_TO,
                        )
                    ],
                )
            ]
        ),
    ),
    Scenario(
        "observation_self_loop_omitted",
        # f1 and f2 share one subject; the correlation relationship between
        # them must not become a self-loop edge.
        summary([finding("f1"), finding("f2", categories=[FindingCategory.EXPOSURE])]),
        correlation_summary(
            [
                observation(
                    "cor_3",
                    evidence_items=[
                        correlation_evidence("f1"),
                        correlation_evidence("f2", matched_category=FindingCategory.EXPOSURE),
                    ],
                    relationships=[
                        correlation_relationship(source_finding_id="f1", target_finding_id="f2")
                    ],
                )
            ]
        ),
    ),
    Scenario(
        "observation_relationship_unknown_finding_skipped",
        # The relationship references "f9", which the observation's own
        # evidence never cites — the direct edge must be skipped gracefully.
        summary([finding("f1")]),
        correlation_summary(
            [
                observation(
                    "cor_4",
                    evidence_items=[correlation_evidence("f1")],
                    relationships=[
                        correlation_relationship(source_finding_id="f1", target_finding_id="f9")
                    ],
                )
            ]
        ),
    ),
    Scenario(
        "multiple_observations_share_entity_node",
        summary(
            [
                finding("f1"),
                finding("f2", categories=[FindingCategory.EXPOSURE]),
            ]
        ),
        correlation_summary(
            [
                observation("cor_5", evidence_items=[correlation_evidence("f1")]),
                observation(
                    "cor_6",
                    evidence_items=[
                        correlation_evidence("f2", matched_category=FindingCategory.EXPOSURE)
                    ],
                ),
            ]
        ),
    ),
    Scenario(
        "severity_is_worst_across_findings_on_same_subject",
        summary(
            [
                finding("f1", severity=Severity.LOW),
                finding("f2", categories=[FindingCategory.REPUTATION], severity=Severity.CRITICAL),
            ]
        ),
    ),
    Scenario(
        "relationship_target_only_entity_has_no_severity",
        summary([finding("f1", severity=Severity.HIGH, relationships=[relationship()])]),
    ),
    Scenario(
        "correlation_present_but_empty_observations",
        summary([finding("f1")]),
        correlation_summary([]),
    ),
    Scenario(
        "relationship_with_no_description",
        summary(
            [
                finding(
                    "f1",
                    relationships=[relationship(description=None, target_value="Trickbot")],
                )
            ]
        ),
    ),
    Scenario(
        "finding_relationship_and_correlation_hub_share_a_subject",
        # f1 and f2 share one subject; f1 also carries an explicit
        # finding-level relationship to a malware family. A correlation
        # observation cites both findings (contributing hub edges) and
        # asserts a same-subject CorrelationRelationship between them (still
        # omitted as a self-loop) — exercising both collection passes, and
        # their interaction on one shared entity, in a single investigation.
        summary(
            [
                finding("f1", relationships=[relationship()]),
                finding("f2", categories=[FindingCategory.EXPOSURE], severity=Severity.MEDIUM),
            ]
        ),
        correlation_summary(
            [
                observation(
                    "cor_combined",
                    evidence_items=[
                        correlation_evidence("f1"),
                        correlation_evidence("f2", matched_category=FindingCategory.EXPOSURE),
                    ],
                    relationships=[
                        correlation_relationship(
                            source_finding_id="f1",
                            target_finding_id="f2",
                            rel_type=CorrelationRelationshipType.EXPOSES,
                        )
                    ],
                )
            ]
        ),
    ),
)
