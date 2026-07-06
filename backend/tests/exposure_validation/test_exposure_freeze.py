"""Exposure Engine v1.0 freeze tests (Phase 5.4).

Runs the full corpus through the real, unmodified ``ExposureRegistry`` +
``ExposureService`` (the exact code path ``GET /api/v1/exposure`` uses),
asserting the freeze invariants and a stable golden snapshot. Regenerate the
golden intentionally with ``THREATLENS_UPDATE_GOLDEN=1 pytest``.
"""

from __future__ import annotations

import importlib
import json
import os
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from threatlens.api.app import app
from threatlens.exposure import EXPOSURE_FRAMEWORK_VERSION, ExposureRegistry, ExposureService

from .corpus import _CATEGORIES, _SHAPES, CORPUS, Scenario
from .harness import snapshot, validate_scenario

_GOLDEN = Path(__file__).with_name("golden.json")
_UPDATE = os.environ.get("THREATLENS_UPDATE_GOLDEN") == "1"

# threatlens.api's __init__ does `from .app import app`, which rebinds the
# `app` attribute on the `threatlens.api` package to the FastAPI instance —
# see tests/exposure/test_api.py for the full explanation of why importlib
# (not an attribute-chain import) is required to reach the actual module.
app_module = importlib.import_module("threatlens.api.app")
client = TestClient(app)


def _use_registry(monkeypatch: pytest.MonkeyPatch, registry: ExposureRegistry) -> None:
    monkeypatch.setattr(app_module, "_exposure_registry", registry)
    monkeypatch.setattr(app_module, "_exposure_service", ExposureService(registry))


# --------------------------------------------------------------------------- #
# Corpus shape & freeze marker
# --------------------------------------------------------------------------- #


def test_corpus_size_within_bounds() -> None:
    assert 100 <= len(CORPUS) <= 200, f"corpus has {len(CORPUS)} scenarios"


def test_corpus_ids_unique() -> None:
    ids = [s.id for s in CORPUS]
    assert len(ids) == len(set(ids))


def test_corpus_covers_every_requested_category() -> None:
    categories = {s.category for s in CORPUS}
    required = {c for c, _ in _CATEGORIES}
    assert required <= categories


def test_corpus_covers_every_provider_matrix_shape() -> None:
    covered = {s.id.split("__", 1)[1] for s in CORPUS if s.category != "special"}
    assert covered == {name for name, _ in _SHAPES}


def test_corpus_exercises_every_provider_name() -> None:
    seen = {name for s in CORPUS for name in s.expect_provider_order}
    assert seen == {"censys", "greynoise", "shodan"}


def test_engine_is_frozen_at_v1() -> None:
    assert EXPOSURE_FRAMEWORK_VERSION == "1.0"


# --------------------------------------------------------------------------- #
# Per-scenario invariants
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("scenario", CORPUS, ids=lambda s: s.id)
def test_scenario_invariants(scenario: Scenario) -> None:
    problems = validate_scenario(scenario)
    assert not problems, f"{scenario.id}:\n  " + "\n  ".join(problems)


# --------------------------------------------------------------------------- #
# Determinism (same scenario -> identical content-level snapshot)
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("scenario", CORPUS, ids=lambda s: s.id)
def test_scenario_is_deterministic(scenario: Scenario) -> None:
    assert snapshot(scenario) == snapshot(scenario), f"{scenario.id}: non-deterministic output"


# --------------------------------------------------------------------------- #
# Golden regression
# --------------------------------------------------------------------------- #


def _current_golden() -> dict[str, Any]:
    return {scenario.id: snapshot(scenario) for scenario in CORPUS}


def test_golden_regression() -> None:
    current = _current_golden()
    if _UPDATE:
        _GOLDEN.write_text(json.dumps(current, indent=2, sort_keys=True) + "\n")
        pytest.skip("exposure golden regenerated (THREATLENS_UPDATE_GOLDEN=1)")

    assert _GOLDEN.exists(), "golden.json missing — run with THREATLENS_UPDATE_GOLDEN=1"
    golden = json.loads(_GOLDEN.read_text())
    assert set(current) == set(golden), "corpus changed; regenerate the golden snapshot"
    drifted = [sid for sid in current if current[sid] != golden[sid]]
    assert not drifted, (
        "Exposure output drifted for: "
        + ", ".join(drifted)
        + " (regenerate intentionally with THREATLENS_UPDATE_GOLDEN=1 and bump the engine version)"
    )


# --------------------------------------------------------------------------- #
# API contract — a representative subset through the real HTTP endpoint
# --------------------------------------------------------------------------- #


class TestApiContract:
    """A few corpus scenarios driven through the real ``GET /api/v1/exposure``.

    Per-scenario model-level contract checks already run for all 153
    scenarios in ``test_scenario_invariants``; this proves the same contract
    survives the FastAPI/HTTP layer for a representative sample, without
    paying for 153 HTTP round-trips.
    """

    _REPRESENTATIVE_IDS = (
        "public_infrastructure__all_three_success",
        "cloud_provider__mixed_outcomes",
        "special__empty_registry",
        "special__unsupported_entity_type",
        "special__provider_raises_exception",
    )

    @pytest.mark.parametrize("scenario_id", _REPRESENTATIVE_IDS)
    def test_endpoint_matches_model_level_summary(
        self, monkeypatch: pytest.MonkeyPatch, scenario_id: str
    ) -> None:
        scenario = next(s for s in CORPUS if s.id == scenario_id)
        registry = ExposureRegistry()
        for provider in scenario.providers:
            registry.register(provider)
        _use_registry(monkeypatch, registry)

        res = client.get("/api/v1/exposure", params={"value": scenario.entity_value})
        assert res.status_code == 200
        body = res.json()
        assert body["providers_registered"] == len(scenario.providers)

        summary = body["summary"]
        assert summary is not None
        assert summary["statistics"]["providers_queried"] == scenario.expect_providers_queried
        assert [f["provider"] for f in summary["findings"]] == list(scenario.expect_provider_order)

    def test_disabled_registry_status_probe_is_well_formed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _use_registry(monkeypatch, ExposureRegistry())
        res = client.get("/api/v1/exposure")
        assert res.status_code == 200
        body = res.json()
        assert body["providers_registered"] == 0
        assert body["summary"] is None
