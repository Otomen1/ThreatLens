"""Golden regression for the Correlation Engine over the scenario corpus.

Snapshots every scenario's ``CorrelationSummary`` (excluding the inherited
``generated_at``, which is identity-independent) so any unintended change to
the seed rules, the evaluator, ordering, or identity turns CI red until the
golden is intentionally regenerated. Regenerate with
``THREATLENS_UPDATE_GOLDEN=1 pytest``.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

from threatlens.correlation import correlate
from threatlens.correlation.engine import CORRELATION_FRAMEWORK_VERSION

from .corpus import CORPUS, Scenario

_GOLDEN = Path(__file__).with_name("golden.json")
_UPDATE = os.environ.get("THREATLENS_UPDATE_GOLDEN") == "1"


def _snapshot(scenario: Scenario) -> dict[str, Any]:
    """A stable, timestamp-free view of one scenario's correlation output."""
    result = correlate(scenario.summary)
    return {
        "id": result.id,
        "entity": [result.entity_type.value, result.entity_value],
        "statistics": {
            "rules_evaluated": result.statistics.rules_evaluated,
            "rules_matched": result.statistics.rules_matched,
            "total_observations": result.statistics.total_observations,
            "source_finding_count": result.statistics.source_finding_count,
            "categories": sorted(c.value for c in result.statistics.categories),
        },
        "observations": [
            {
                "id": o.id,
                "rule_id": o.rule_id,
                "category": o.category.value,
                "subject": [o.subject_type.value, o.subject_value],
                "source_finding_ids": list(o.source_finding_ids),
                "evidence": [[e.finding_id, e.matched_category.value] for e in o.evidence],
                "relationships": [
                    [r.type.value, r.source_finding_id, r.target_finding_id]
                    for r in o.relationships
                ],
            }
            for o in result.observations
        ],
        "matches": [[m.rule_id, list(m.observation_ids)] for m in result.matches],
    }


def _current_golden() -> dict[str, Any]:
    return {scenario.id: _snapshot(scenario) for scenario in CORPUS}


def test_corpus_ids_unique() -> None:
    ids = [s.id for s in CORPUS]
    assert len(ids) == len(set(ids))


def test_engine_framework_version_is_pre_1_0() -> None:
    assert CORRELATION_FRAMEWORK_VERSION == "0.1.0"


def test_golden_regression() -> None:
    current = _current_golden()
    if _UPDATE:
        _GOLDEN.write_text(json.dumps(current, indent=2, sort_keys=True) + "\n")
        pytest.skip("correlation golden regenerated (THREATLENS_UPDATE_GOLDEN=1)")

    assert _GOLDEN.exists(), "golden.json missing — run with THREATLENS_UPDATE_GOLDEN=1"
    golden = json.loads(_GOLDEN.read_text())
    assert set(current) == set(golden), "corpus changed; regenerate the golden snapshot"
    drifted = [sid for sid in current if current[sid] != golden[sid]]
    assert not drifted, (
        "Correlation output drifted for: "
        + ", ".join(drifted)
        + " (regenerate intentionally with THREATLENS_UPDATE_GOLDEN=1 and bump the engine version)"
    )
