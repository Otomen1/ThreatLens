"""Golden regression for the Detection Knowledge Library (Phase 4.6).

Snapshots normalization + matching for the whole seed corpus and every scenario.
Any drift fails CI until intentionally regenerated with
``THREATLENS_UPDATE_GOLDEN=1 pytest``.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from .harness import build_golden

_GOLDEN = Path(__file__).with_name("golden.json")
_UPDATE = os.environ.get("THREATLENS_UPDATE_GOLDEN") == "1"


def test_golden_regression() -> None:
    current = build_golden()
    if _UPDATE:
        _GOLDEN.write_text(json.dumps(current, indent=2, sort_keys=True) + "\n")
        pytest.skip("detection-library golden regenerated (THREATLENS_UPDATE_GOLDEN=1)")

    assert _GOLDEN.exists(), "golden.json missing — run with THREATLENS_UPDATE_GOLDEN=1"
    golden = json.loads(_GOLDEN.read_text())

    assert set(current["rules"]) == set(golden["rules"]), "normalized rule set changed"
    assert set(current["recommendations"]) == set(golden["recommendations"])

    drifted_rules = [
        rid for rid in current["rules"] if current["rules"][rid] != golden["rules"][rid]
    ]
    assert not drifted_rules, f"normalization drifted for: {drifted_rules}"

    drifted_recs = [
        sid
        for sid in current["recommendations"]
        if current["recommendations"][sid] != golden["recommendations"][sid]
    ]
    assert not drifted_recs, (
        "matching drifted for: "
        + ", ".join(drifted_recs)
        + " (regenerate intentionally with THREATLENS_UPDATE_GOLDEN=1)"
    )
