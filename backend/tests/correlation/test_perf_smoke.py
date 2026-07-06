"""Smoke test: the correlation perf harness runs (no timing assertions in CI).

Timing thresholds are environment-dependent and would flake on shared runners,
so CI only verifies the harness executes and reports sane shapes. The latency
numbers come from running ``perf.py`` and are recorded in the Phase 7.0
architecture document.
"""

from __future__ import annotations

from .perf import _summary, measure_scaling


def test_scaling_harness_runs_and_reports_every_size() -> None:
    rows = measure_scaling()
    # Each size produces exactly that many observations (one per subject).
    assert [int(r["observations"]) for r in rows] == [10, 50, 100, 500]
    for row in rows:
        assert row["findings"] == row["observations"] * 2  # malicious + exposure per subject
        assert row["median_ms"] >= 0.0
        assert row["peak_kib"] > 0.0


def test_summary_builder_produces_one_observation_per_subject() -> None:
    source = _summary(37)
    assert len(source.findings) == 74  # 2 findings per subject
    assert len({f.id for f in source.findings}) == 74
