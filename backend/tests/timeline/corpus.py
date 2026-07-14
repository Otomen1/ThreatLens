"""A small, curated scenario corpus for the Timeline Engine's golden regression.

Deliberately small relative to Correlation's 76-scenario corpus: the
Timeline Engine's behavior space is narrow (extract-if-timestamped,
dedupe-by-content, sort-deterministically) rather than a combinatorial rule
library, so a focused set of scenarios exercising every documented policy
decision (missing timestamp, invalid timestamp, duplicate evidence, ties,
multiple sources, empty) gives the same regression-locking value Correlation's
larger corpus gives its larger rule surface.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from threatlens.providers.results import EvidenceType
from threatlens.reasoning.models import FindingCategory, InvestigationSummary, Severity

from .factories import evidence, finding, summary

T1 = datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC)
T2 = datetime(2024, 1, 2, 12, 0, 0, tzinfo=UTC)
T3 = datetime(2024, 1, 3, 12, 0, 0, tzinfo=UTC)
NAIVE = datetime(2024, 1, 4, 0, 0, 0)  # deliberately missing tzinfo


@dataclass(frozen=True)
class Scenario:
    id: str
    summary: InvestigationSummary


CORPUS: tuple[Scenario, ...] = (
    Scenario("empty_investigation", summary([])),
    Scenario("finding_with_no_evidence", summary([finding("f1", evidence_items=[])])),
    Scenario(
        "single_timestamped_evidence",
        summary([finding("f1", evidence_items=[evidence("Malicious per feed", T1, value="95")])]),
    ),
    Scenario(
        "missing_timestamp_omitted",
        summary([finding("f1", evidence_items=[evidence("No timestamp", None)])]),
    ),
    Scenario(
        "naive_timestamp_omitted",
        summary([finding("f1", evidence_items=[evidence("Naive timestamp", NAIVE)])]),
    ),
    Scenario(
        "mixed_valid_and_invalid",
        summary(
            [
                finding(
                    "f1",
                    evidence_items=[
                        evidence("Valid", T1),
                        evidence("Missing", None),
                        evidence("Naive", NAIVE),
                    ],
                )
            ]
        ),
    ),
    Scenario(
        "duplicate_evidence_across_findings",
        summary(
            [
                finding(
                    "f1", severity=Severity.HIGH, evidence_items=[evidence("Shared", T1, value="X")]
                ),
                finding(
                    "f2",
                    categories=[FindingCategory.REPUTATION],
                    severity=Severity.CRITICAL,
                    evidence_items=[evidence("Shared", T1, value="X")],
                ),
            ]
        ),
    ),
    Scenario(
        "multiple_findings_distinct_evidence",
        summary(
            [
                finding("f1", evidence_items=[evidence("A", T1)]),
                finding(
                    "f2",
                    categories=[FindingCategory.REPUTATION],
                    subject_value="9.9.9.9",
                    evidence_items=[evidence("B", T2)],
                ),
                finding(
                    "f3",
                    categories=[FindingCategory.VULNERABILITY],
                    subject_value="9.9.9.9",
                    evidence_items=[evidence("C", T3)],
                ),
            ]
        ),
    ),
    Scenario(
        "equal_timestamps_tie_break",
        summary(
            [
                finding(
                    "f1",
                    evidence_items=[
                        evidence("Z", T1, evidence_type=EvidenceType.TAG, value="1"),
                        evidence("A", T1, evidence_type=EvidenceType.BLOCKLIST, value="2"),
                    ],
                )
            ]
        ),
    ),
    Scenario(
        "one_finding_multiple_evidence_items",
        summary([finding("f1", evidence_items=[evidence("A", T2), evidence("B", T1)])]),
    ),
)
