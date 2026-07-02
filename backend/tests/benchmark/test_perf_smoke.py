"""Smoke test: the performance harness runs (no timing assertions in CI).

Timing thresholds are environment-dependent and would flake on shared runners, so
CI only verifies the harness still executes and reports every pipeline stage. The
actual latency numbers are produced by running ``perf.py`` and recorded in the
Reasoning Engine v1.0 architecture document.
"""

from __future__ import annotations

from .perf import measure_all

_EXPECTED_STAGES = {
    "entity_detection",
    "provider_routing_ti",
    "provider_routing_reference",
    "aggregation",
    "evidence_assembly",
    "confidence_scoring",
    "finding_generation",
    "recommendation_rollup",
    "reason_end_to_end",
}


def test_perf_harness_runs_and_reports_all_stages() -> None:
    results = measure_all(iterations=3)
    assert set(results) == _EXPECTED_STAGES
    for stats in results.values():
        assert stats["median_us"] >= 0.0
        assert stats["iterations"] == 3.0
