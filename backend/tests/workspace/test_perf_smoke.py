"""Smoke test: the Workspace Platform perf harness runs (no timing assertions
in CI).

Timing thresholds are environment-dependent and would flake on shared
runners, so CI only verifies the harness executes and reports sane shapes.
The latency numbers come from running ``perf.py`` and are recorded in
``docs/architecture/WORKSPACE-PLATFORM.md``.
"""

from __future__ import annotations

from .perf import (
    _SIZES,
    measure_graph_projection,
    measure_report_and_export,
    measure_timeline_projection,
    measure_workspace_persistence,
)


def test_workspace_persistence_harness_runs_and_reports_every_size() -> None:
    rows = measure_workspace_persistence()
    assert [int(r["findings"]) for r in rows] == list(_SIZES)
    for row in rows:
        assert row["save_median_ms"] >= 0.0
        assert row["load_median_ms"] >= 0.0
        assert row["peak_kib"] > 0.0


def test_timeline_projection_harness_runs_and_reports_every_size() -> None:
    rows = measure_timeline_projection()
    assert [int(r["findings"]) for r in rows] == list(_SIZES)
    for row in rows:
        # One evidence item per finding => one event per finding (no dedup collisions).
        assert row["events"] == row["findings"]
        assert row["median_ms"] >= 0.0
        assert row["peak_kib"] > 0.0


def test_graph_projection_harness_runs_and_reports_every_size() -> None:
    rows = measure_graph_projection()
    assert [int(r["findings"]) for r in rows] == list(_SIZES)
    for row in rows:
        # Each finding has a distinct subject => one node per finding.
        assert row["nodes"] == row["findings"]
        assert row["median_ms"] >= 0.0
        assert row["peak_kib"] > 0.0


def test_report_and_export_harness_runs_and_reports_every_size() -> None:
    rows = measure_report_and_export()
    assert [int(r["findings"]) for r in rows] == list(_SIZES)
    for row in rows:
        assert row["build_median_ms"] >= 0.0
        assert row["export_median_ms"] >= 0.0
        assert row["peak_kib"] > 0.0
