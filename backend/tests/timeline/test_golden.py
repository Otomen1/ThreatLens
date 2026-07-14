"""Golden regression for the Timeline Engine over the scenario corpus.

Snapshots every scenario's derived events (excluding the source summary's own
``generated_at``, which the ``Timeline`` wrapper merely inherits and which is
identity-independent here) so any unintended change to timestamp policy,
deduplication, ordering, or identity turns CI red until the golden is
intentionally regenerated. Regenerate with ``THREATLENS_UPDATE_GOLDEN=1 pytest``.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

from threatlens.timeline.engine import TIMELINE_ENGINE_VERSION, collect_events

from .corpus import CORPUS, Scenario

_GOLDEN = Path(__file__).with_name("golden.json")
_UPDATE = os.environ.get("THREATLENS_UPDATE_GOLDEN") == "1"


def _snapshot(scenario: Scenario) -> dict[str, Any]:
    """A stable, timestamp-format-independent view of one scenario's events."""
    events = collect_events(scenario.summary)
    return {
        "event_count": len(events),
        "events": [
            {
                "event_id": e.event_id,
                "timestamp": e.timestamp.isoformat(),
                "event_type": e.event_type.value,
                "title": e.title,
                "description": e.description,
                "source_type": e.source_type.value,
                "source_id": e.source_id,
                "severity": int(e.severity) if e.severity is not None else None,
                "evidence_references": list(e.evidence_references),
            }
            for e in events
        ],
    }


def _current_golden() -> dict[str, Any]:
    return {scenario.id: _snapshot(scenario) for scenario in CORPUS}


def test_corpus_ids_unique() -> None:
    ids = [s.id for s in CORPUS]
    assert len(ids) == len(set(ids))


def test_engine_version_unchanged() -> None:
    assert TIMELINE_ENGINE_VERSION == "1.0"


def test_golden_regression() -> None:
    current = _current_golden()
    if _UPDATE:
        _GOLDEN.write_text(json.dumps(current, indent=2, sort_keys=True) + "\n")
        pytest.skip("timeline golden regenerated (THREATLENS_UPDATE_GOLDEN=1)")

    assert _GOLDEN.exists(), "golden.json missing — run with THREATLENS_UPDATE_GOLDEN=1"
    golden = json.loads(_GOLDEN.read_text())
    assert set(current) == set(golden), "corpus changed; regenerate the golden snapshot"
    drifted = [sid for sid in current if current[sid] != golden[sid]]
    assert not drifted, (
        "Timeline output drifted for: "
        + ", ".join(drifted)
        + " (regenerate intentionally with THREATLENS_UPDATE_GOLDEN=1 and bump the engine version)"
    )
