"""Smoke test: the detection perf harness runs (no timing assertions in CI).

Timing thresholds are environment-dependent and would flake on shared runners, so
CI only verifies the harness still executes, scales monotonically, and reports a
per-generator breakdown. The actual latency numbers come from running ``perf.py``
and are recorded in the Detection Engine v1.0 architecture document.
"""

from __future__ import annotations

from threatlens.detection import build_default_registry

from .perf import _summary, measure_per_generator, measure_scaling


def test_scaling_harness_runs_and_grows_with_size() -> None:
    rows = measure_scaling()
    assert [int(r["findings"]) for r in rows] == [1, 10, 50, 100, 500, 1000]
    # More findings must never yield fewer rules (monotic fan-out) and cost time.
    rules = [r["rules"] for r in rows]
    assert rules == sorted(rules)
    for row in rows:
        assert row["rules"] > 0
        assert row["median_ms"] >= 0.0
        assert row["peak_kib"] > 0.0


def test_per_generator_breakdown_covers_every_generator() -> None:
    names = {g.name for g in build_default_registry().generators}
    rows = measure_per_generator(n=20)
    assert {r["generator"] for r in rows} == names
    # Sorted largest-contributor first.
    medians = [float(r["median_ms"]) for r in rows]
    assert medians == sorted(medians, reverse=True)


def test_summary_builder_is_pure_and_sized() -> None:
    assert len(_summary(37).findings) == 37
    assert len({f.id for f in _summary(37).findings}) == 37
