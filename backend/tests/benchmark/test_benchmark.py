"""Reasoning-engine regression benchmark (Phase 3.15).

Runs every :data:`scenarios.SCENARIOS` case through :func:`threatlens.reasoning.reason`
at a fixed ``NOW`` and verifies:

* the declarative expectations (posture, overall confidence band/contested,
  per-finding category/severity/confidence/priority, ordered recommendation
  actions) — the intent of each scenario, hand-derived from the frozen models;
* determinism (identical output across two independent calls);
* stable, content-addressed finding identity;
* a full golden snapshot of every output (findings/severity/confidence/
  recommendations/priority) — the byte-level drift guard. Regenerate it
  deliberately with ``THREATLENS_UPDATE_GOLDEN=1 pytest`` after an intended change.

The whole module is offline and part of CI, so any unintended change to engine
output fails the build.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

from threatlens.reasoning import InvestigationSummary, reason

from .scenarios import NOW, SCENARIOS, Scenario

_GOLDEN_PATH = Path(__file__).with_name("golden.json")
_UPDATE = os.environ.get("THREATLENS_UPDATE_GOLDEN") == "1"

# A representative content-addressed id: changing the identity algorithm or the
# canonical evidence of this scenario breaks the freeze guarantee loudly.
_CVE_CRITICAL_FINDING_ID = "fnd_f8256ec5649e65b0"


def _run(scenario: Scenario) -> InvestigationSummary:
    return reason(
        scenario.entity, scenario.ti, scenario.knowledge, context=scenario.context, now=NOW
    )


# --------------------------------------------------------------------------- #
# Corpus shape
# --------------------------------------------------------------------------- #


def test_corpus_size_within_bounds() -> None:
    """The benchmark holds 50–100 scenarios (the spec's coverage target)."""
    assert 50 <= len(SCENARIOS) <= 100, f"benchmark has {len(SCENARIOS)} scenarios"


def test_scenario_ids_unique() -> None:
    ids = [s.id for s in SCENARIOS]
    assert len(ids) == len(set(ids))


# --------------------------------------------------------------------------- #
# Declarative expectations
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: s.id)
def test_scenario_expectations(scenario: Scenario) -> None:
    summary = _run(scenario)

    assert summary.posture is scenario.posture, f"{scenario.id}: posture"
    assert summary.overall_confidence.band is scenario.overall_band, f"{scenario.id}: overall band"
    if scenario.overall_contested is not None:
        assert summary.overall_confidence.contested is scenario.overall_contested, (
            f"{scenario.id}: overall contested"
        )

    assert len(summary.findings) == scenario.finding_count, (
        f"{scenario.id}: expected {scenario.finding_count} findings, "
        f"got {[sorted(c.value for c in f.categories) for f in summary.findings]}"
    )

    remaining = list(summary.findings)
    for expected in scenario.findings:
        idx = next(
            (
                i
                for i, f in enumerate(remaining)
                if expected.category in f.categories
                and f.severity is expected.severity
                and f.confidence.band is expected.band
                and f.confidence.contested is expected.contested
            ),
            None,
        )
        assert idx is not None, (
            f"{scenario.id}: no finding matches {expected.category.value}/"
            f"{expected.severity.name}/{expected.band.value}/contested={expected.contested}"
        )
        finding = remaining.pop(idx)
        if expected.priority is not None:
            assert finding.priority == expected.priority, (
                f"{scenario.id}: {expected.category.value} priority "
                f"{finding.priority} != {expected.priority}"
            )
        if expected.min_recommendations:
            assert len(finding.recommendations) >= expected.min_recommendations, (
                f"{scenario.id}: {expected.category.value} recommendations"
            )
    assert not remaining, f"{scenario.id}: unmatched findings remain"

    if scenario.rollup is not None:
        actions = [rec.action for rec in summary.recommendations]
        assert actions == list(scenario.rollup), f"{scenario.id}: rollup ordering"


# --------------------------------------------------------------------------- #
# Determinism & identity
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: s.id)
def test_scenario_is_deterministic(scenario: Scenario) -> None:
    assert _run(scenario) == _run(scenario), f"{scenario.id}: non-deterministic output"


@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: s.id)
def test_finding_ids_are_content_addressed(scenario: Scenario) -> None:
    for finding in _run(scenario).findings:
        assert finding.id.startswith("fnd_"), f"{scenario.id}: id prefix"
        assert len(finding.id) == 20, f"{scenario.id}: id length"  # 'fnd_' + 16 hex


def test_representative_finding_id_is_stable() -> None:
    """A pinned id guards the finding-identity algorithm against silent change."""
    summary = _run(next(s for s in SCENARIOS if s.id == "cve_critical"))
    assert summary.findings[0].id == _CVE_CRITICAL_FINDING_ID


# --------------------------------------------------------------------------- #
# Golden snapshot — exhaustive byte-level drift guard
# --------------------------------------------------------------------------- #


def _snapshot(summary: InvestigationSummary) -> dict[str, Any]:
    """A compact, stable view of one summary (no timestamps, no free text)."""
    return {
        "posture": int(summary.posture),
        "confidence": _confidence(summary.overall_confidence),
        "categories": sorted(c.value for c in summary.categories),
        "findings": [
            {
                "id": f.id,
                "categories": sorted(c.value for c in f.categories),
                "subject": [f.subject_type.value, f.subject_value],
                "severity": int(f.severity),
                "confidence": _confidence(f.confidence),
                "priority": f.priority,
                "rule_ids": list(f.rule_ids),
                "recommendations": [
                    {"action": r.action.value, "category": r.category.value, "priority": r.priority}
                    for r in f.recommendations
                ],
            }
            for f in summary.findings
        ],
        "rollup": [
            {
                "action": r.action.value,
                "category": r.category.value,
                "priority": r.priority,
                "finding_ids": sorted(r.finding_ids),
            }
            for r in summary.recommendations
        ],
    }


def _confidence(confidence: Any) -> dict[str, Any]:
    return {
        "score": confidence.score,
        "band": confidence.band.value,
        "contested": confidence.contested,
    }


def _current_golden() -> dict[str, Any]:
    return {s.id: _snapshot(_run(s)) for s in SCENARIOS}


def test_golden_snapshot_matches() -> None:
    current = _current_golden()
    if _UPDATE:
        _GOLDEN_PATH.write_text(json.dumps(current, indent=2, sort_keys=True) + "\n")
        pytest.skip("golden snapshot regenerated (THREATLENS_UPDATE_GOLDEN=1)")

    assert _GOLDEN_PATH.exists(), "golden.json missing — run with THREATLENS_UPDATE_GOLDEN=1"
    golden = json.loads(_GOLDEN_PATH.read_text())

    assert set(current) == set(golden), "scenario set changed; regenerate the golden snapshot"
    mismatches = [sid for sid in current if current[sid] != golden[sid]]
    assert not mismatches, (
        "engine output drifted for: "
        + ", ".join(mismatches)
        + " (regenerate intentionally with THREATLENS_UPDATE_GOLDEN=1)"
    )
