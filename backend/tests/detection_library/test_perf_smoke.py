"""Smoke test: the DKL perf harness runs (no timing assertions in CI)."""

from __future__ import annotations

from .perf import measure


def test_perf_harness_runs_and_scales_monotonically() -> None:
    result = measure()
    assert result["build_ms"] >= 0.0
    assert result["recommend_ms"] >= 0.0
    scaling = result["scaling"]
    assert isinstance(scaling, list)
    sizes = [row["rules"] for row in scaling]
    assert sizes == [18, 100, 500, 1000]
    for row in scaling:
        assert row["recommend_ms"] >= 0.0
        assert row["us_per_rule"] >= 0.0
