"""Performance benchmarks for the Correlation Engine (Phase 7.0 + Phase 7.1).

Two independent scaling dimensions, each isolating one variable:

* :func:`measure_scaling` (Phase 7.0) — a *fixed* rule count (the real
  default registry), growing observation count (10 -> 500). Each size builds
  ``n`` distinct subjects, each carrying a malicious-infrastructure and an
  exposure finding, so the same-subject ``malicious_exposed_infrastructure``
  rule fires exactly once per subject -> exactly ``n`` observations from
  ``2n`` findings.
* :func:`measure_rule_scaling` (Phase 7.1) — a *fixed*, small investigation,
  growing registered rule count (25 -> 100), using synthetic rules built only
  for this benchmark (never registered in the real default registry) so the
  measurement isolates "cost per rule evaluated" from "cost per observation
  produced". Confirms rule-library growth stays linear in the number of
  rules, independent of the Phase 7.0 observation-scaling result above.

Both report per-call wall time, peak allocation, and an amortised
per-unit cost. The engine is pure and offline (no I/O, no AI, no clock), so
the numbers are stable enough to reason about scaling. Run the report::

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
from itertools import combinations

from threatlens.correlation import correlate
from threatlens.correlation.models import CorrelationCategory, CorrelationRelationshipType
from threatlens.correlation.models import CorrelationRule as Rule
from threatlens.correlation.registry import CorrelationRegistry
from threatlens.correlation.rules import SEED_RULES
from threatlens.entities.types import EntityType
from threatlens.reasoning.models import Finding, InvestigationSummary
from threatlens.reasoning.models import FindingCategory as FC

from .factories import finding, summary

_SIZES = (10, 50, 100, 500)
_RULE_COUNTS = (25, 50, 100)


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


def _synthetic_registry(n: int) -> CorrelationRegistry:
    """A registry of ``n`` synthetic, benchmark-only rules.

    Cycles through every 2-category combination of the 15 real
    ``FindingCategory`` values so each rule is schema-valid, never repeating a
    combination within one registry (``n`` is capped well under
    ``C(15, 2) = 105`` by every caller). These rules are never registered in
    the real default registry and never appear in the rule library's golden
    snapshot — they exist only to isolate "cost per rule evaluated" from the
    Phase 7.0 observation-scaling benchmark above.
    """
    pairs = list(combinations(sorted(FC, key=lambda c: c.value), 2))
    registry = CorrelationRegistry()
    for i in range(n):
        a, b = pairs[i % len(pairs)]
        registry.register(
            Rule(
                id=f"_bench_synthetic_{i:04d}",
                name=f"benchmark rule {i}",
                description="Synthetic rule for the Phase 7.1 rule-count perf benchmark only.",
                category=CorrelationCategory.MALICIOUS_EXPOSED_INFRASTRUCTURE,
                required_categories=frozenset({a, b}),
                relationship=CorrelationRelationshipType.CO_OCCURS_WITH,
                title=f"benchmark rule {i}",
                priority=1000 + i,
            )
        )
    return registry


def _fixed_small_investigation() -> InvestigationSummary:
    """A small, fixed investigation used for every rule-count benchmark point.

    Deliberately investigation-size-independent: this benchmark varies the
    *registry*, not the input, so every data point runs against identical
    evaluation work per rule.
    """
    return summary(
        [
            finding("fnd_1", {FC.MALICIOUS_INFRASTRUCTURE, FC.EXPOSURE}),
            finding("fnd_2", {FC.VULNERABILITY}),
            finding("fnd_3", {FC.KNOWN_EXPLOITED}),
            finding("fnd_4", {FC.REPUTATION}),
            finding("fnd_5", {FC.MISCONFIGURATION}),
        ]
    )


def measure_rule_scaling() -> list[dict[str, float]]:
    """Time and memory for ``correlate`` across growing *registered rule* counts.

    Uses the same fixed investigation at every size (see
    :func:`_fixed_small_investigation`) so only the registry size varies.
    """
    source = _fixed_small_investigation()
    rows: list[dict[str, float]] = []
    for n in _RULE_COUNTS:
        registry = _synthetic_registry(n)
        run = partial(correlate, source, registry=registry)
        median_ms, mean_ms = _bench(run, _iterations(n))
        peak = _peak_kib(run)
        rows.append(
            {
                "rules": float(n),
                "median_ms": median_ms,
                "mean_ms": mean_ms,
                "us_per_rule": (median_ms * 1e3 / n),
                "peak_kib": peak,
            }
        )
    return rows


def main() -> None:
    print("Correlation Engine — correlate() scaling (pure, offline)\n")
    print("-- Phase 7.0: fixed rule count, growing observation count --\n")
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

    print("\n-- Phase 7.1: fixed investigation, growing registered rule count --\n")
    print(f"{'rules':>8} {'median':>10} {'mean':>10} {'us/rule':>9} {'peakKiB':>9}")
    print("-" * 50)
    rule_rows = measure_rule_scaling()
    for r in rule_rows:
        print(
            f"{int(r['rules']):>8} {r['median_ms']:>8.3f}ms {r['mean_ms']:>8.3f}ms "
            f"{r['us_per_rule']:>9.2f} {r['peak_kib']:>9.1f}"
        )

    per_rule = [r["us_per_rule"] for r in rule_rows]
    rule_spread = max(per_rule) / min(per_rule)
    rule_verdict = "linear" if rule_spread <= 3.0 else "super-linear (investigate)"
    print(f"\nper-rule cost spread across sizes: {rule_spread:.2f}x  -> {rule_verdict}")
    print(f"\n(for reference, the real rule library registers {len(SEED_RULES)} rules)")


if __name__ == "__main__":
    main()
