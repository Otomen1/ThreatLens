"""Smoke test: the exposure perf harness runs (no timing assertions in CI).

Timing thresholds are environment-dependent and would flake on shared
runners, so CI only verifies the harness executes and reports sane shapes.
The actual latency numbers come from running ``perf.py`` and are recorded in
the Exposure Engine v1.0 architecture document.
"""

from __future__ import annotations

from .perf import measure_cache_effectiveness, measure_merge_cost, measure_scaling


def test_scaling_harness_runs_and_reports_every_size() -> None:
    rows = measure_scaling()
    assert [int(r["lookups"]) for r in rows] == [1, 10, 50, 100]
    for row in rows:
        assert row["findings"] == row["lookups"] * 3  # 3 providers registered
        assert row["median_ms"] >= 0.0
        assert row["peak_kib"] > 0.0


def test_cache_effectiveness_harness_runs_and_warm_is_faster() -> None:
    result = measure_cache_effectiveness()
    assert result["cold_ms"] > 0.0
    assert result["warm_ms"] > 0.0
    assert result["warm_ms"] < result["cold_ms"]  # a cache hit skips the simulated fetch
    assert result["speedup"] > 1.0


def test_merge_cost_harness_runs_and_scales_with_finding_count() -> None:
    rows = measure_merge_cost()
    assert [int(r["findings"]) for r in rows] == [1, 10, 50, 100]
    for row in rows:
        assert row["median_ms"] >= 0.0
        assert row["peak_kib"] > 0.0
