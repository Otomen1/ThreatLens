"""Performance benchmark for the Correlation Engine (Phase 7.0).

Measures ``correlate`` on investigations that produce a growing number of
observations (10 -> 500). Each size builds ``n`` distinct subjects, each
carrying a malicious-infrastructure and an exposure finding, so the
same-subject ``malicious_exposed_infrastructure`` rule fires exactly once per
subject → exactly ``n`` observations from ``2n`` findings. Reports per-call
wall time, peak allocation, and the amortised cost per observation. The engine
is pure and offline (no I/O, no AI, no clock), so the numbers are stable enough
to reason about scaling. Run the report::

    cd backend && python -m tests.correlation.perf

Exercised (without timing assertions) by ``test_perf_smoke.py`` so it cannot
bit-rot in CI.
"""

from __future__ import annotations

import statistics
import time
import tracemalloc
from collections.abc import Callable
from functools import partial

from threatlens.correlation import correlate
from threatlens.entities.types import EntityType
from threatlens.reasoning.models import Finding, InvestigationSummary
from threatlens.reasoning.models import FindingCategory as FC

from .factories import finding, summary

_SIZES = (10, 50, 100, 500)


def _summary(n: int) -> InvestigationSummary:
    """An investigation of ``n`` subjects, each yielding exactly one observation."""
    findings: list[Finding] = []
    for i in range(n):
        subject = f"10.{i // 250}.{(i // 25) % 10}.{i % 250}"
        findings.append(
            finding(
                f"fnd_{i:05d}m",
                {FC.MALICIOUS_INFRASTRUCTURE},
                subject_type=EntityType.IPV4,
                subject_value=subject,
            )
        )
        findings.append(
            finding(
                f"fnd_{i:05d}e",
                {FC.EXPOSURE},
                subject_type=EntityType.IPV4,
                subject_value=subject,
            )
        )
    return summary(findings)


def _iterations(n: int) -> int:
    return max(3, min(100, 2000 // n))


def _bench(fn: Callable[[], object], iterations: int) -> tuple[float, float]:
    fn()  # warm up
    samples = []
    for _ in range(iterations):
        start = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - start) * 1e3)  # milliseconds
    return statistics.median(samples), statistics.fmean(samples)


def _peak_kib(fn: Callable[[], object]) -> float:
    tracemalloc.start()
    fn()
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return peak / 1024


def measure_scaling() -> list[dict[str, float]]:
    """Time and memory for ``correlate`` across the requested observation counts."""
    rows: list[dict[str, float]] = []
    for n in _SIZES:
        source = _summary(n)
        run = partial(correlate, source)
        observations = len(correlate(source).observations)
        median_ms, mean_ms = _bench(run, _iterations(n))
        peak = _peak_kib(run)
        rows.append(
            {
                "observations": float(observations),
                "findings": float(len(source.findings)),
                "median_ms": median_ms,
                "mean_ms": mean_ms,
                "us_per_observation": (median_ms * 1e3 / n),
                "peak_kib": peak,
            }
        )
    return rows


def main() -> None:
    print("Correlation Engine — correlate() scaling (pure, offline)\n")
    print(
        f"{'observ.':>8} {'findings':>9} {'median':>10} {'mean':>10} {'us/obs':>9} {'peakKiB':>9}"
    )
    print("-" * 60)
    rows = measure_scaling()
    for r in rows:
        print(
            f"{int(r['observations']):>8} {int(r['findings']):>9} "
            f"{r['median_ms']:>8.3f}ms {r['mean_ms']:>8.3f}ms "
            f"{r['us_per_observation']:>9.2f} {r['peak_kib']:>9.1f}"
        )

    per_obs = [r["us_per_observation"] for r in rows]
    spread = max(per_obs) / min(per_obs)
    verdict = "linear" if spread <= 3.0 else "super-linear (investigate)"
    print(f"\nper-observation cost spread across sizes: {spread:.2f}x  -> {verdict}")


if __name__ == "__main__":
    main()
