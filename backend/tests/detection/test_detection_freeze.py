"""Detection Engine v1.0 freeze tests (Phase 4.5).

Runs the full corpus through every generator, asserting the freeze invariants and
a byte-stable golden snapshot. Regenerate the golden intentionally with
``THREATLENS_UPDATE_GOLDEN=1 pytest``.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

from threatlens.detection import DETECTION_ENGINE_VERSION, build_default_registry, generate

from .corpus import CORPUS, Scenario
from .harness import snapshot, validate_scenario
from .validate import native_available, native_validate_yara

_GOLDEN = Path(__file__).with_name("golden.json")
_UPDATE = os.environ.get("THREATLENS_UPDATE_GOLDEN") == "1"

# Every generator whose output the freeze protects.
_EXPECTED_GENERATORS = {
    "sigma",
    "yara",
    "suricata",
    "snort",
    "splunk",
    "sentinel",
    "elastic",
    "chronicle",
    "qradar",
}


# --------------------------------------------------------------------------- #
# Corpus shape & freeze marker
# --------------------------------------------------------------------------- #


def test_corpus_size_and_unique_ids() -> None:
    assert 100 <= len(CORPUS) <= 150, f"corpus has {len(CORPUS)} scenarios"
    ids = [s.id for s in CORPUS]
    assert len(ids) == len(set(ids))


def test_corpus_covers_every_generator() -> None:
    produced: set[str] = set()
    registry = build_default_registry()
    by_lang = {g.language: g.name for g in registry.generators}
    for scenario in CORPUS:
        for artifact in generate(scenario.summary).artifacts:
            produced.add(by_lang[artifact.language])
    assert produced == _EXPECTED_GENERATORS


def test_engine_is_frozen_at_v1() -> None:
    assert DETECTION_ENGINE_VERSION == "1.0"


# --------------------------------------------------------------------------- #
# Per-scenario invariants
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("scenario", CORPUS, ids=lambda s: s.id)
def test_scenario_invariants(scenario: Scenario) -> None:
    problems = validate_scenario(scenario)
    assert not problems, f"{scenario.id}:\n  " + "\n  ".join(problems)


# --------------------------------------------------------------------------- #
# Golden regression (every generator, every scenario)
# --------------------------------------------------------------------------- #


def _current_golden() -> dict[str, Any]:
    return {scenario.id: snapshot(scenario) for scenario in CORPUS}


def test_golden_regression() -> None:
    current = _current_golden()
    if _UPDATE:
        _GOLDEN.write_text(json.dumps(current, indent=2, sort_keys=True) + "\n")
        pytest.skip("detection golden regenerated (THREATLENS_UPDATE_GOLDEN=1)")

    assert _GOLDEN.exists(), "golden.json missing — run with THREATLENS_UPDATE_GOLDEN=1"
    golden = json.loads(_GOLDEN.read_text())
    assert set(current) == set(golden), "corpus changed; regenerate the golden snapshot"
    drifted = [sid for sid in current if current[sid] != golden[sid]]
    assert not drifted, (
        "Detection output drifted for: "
        + ", ".join(drifted)
        + " (regenerate intentionally with THREATLENS_UPDATE_GOLDEN=1 and bump the engine version)"
    )


# --------------------------------------------------------------------------- #
# Optional native validation (skipped unless a toolchain is installed)
# --------------------------------------------------------------------------- #


def test_native_yara_validation_when_available() -> None:
    if not native_available()["yara"]:
        pytest.skip("yara-python not installed — parser-level validation applies (documented)")
    from threatlens.detection import DetectionLanguage  # local import keeps top clean

    for scenario in CORPUS:  # pragma: no cover - only runs when yara is installed
        for artifact in generate(scenario.summary).artifacts:
            if artifact.language is DetectionLanguage.YARA:
                assert native_validate_yara(artifact.content), scenario.id
