"""Performance benchmark for the Detection Engine (Phase 4.5).

Measures ``detection.generate`` on investigations of growing size (1 → 1000
findings), reporting per-call wall time, peak allocation, the number of rules
produced, the amortised cost *per rule*, and — at the largest size — the
per-generator breakdown that identifies the largest contributor.

It is offline and CPU-only (the engine is pure: no I/O, no AI, no clock), so the
numbers are stable enough to reason about scaling. Run the full report::

    python tests/detection/perf.py      # or: python -m tests.detection.perf

The harness is exercised (without timing assertions, at small sizes) by
``test_perf_smoke.py`` so it cannot bit-rot in CI.
"""

from __future__ import annotations

import statistics
import tracemalloc
from collections.abc import Callable
from datetime import UTC, datetime
from time import perf_counter

from threatlens.detection import DetectionArtifact, build_default_registry, generate
from threatlens.entities.types import EntityType
from threatlens.providers.aggregation import AttributedRelationship
from threatlens.providers.results import (
    Relationship,
    RelationshipTargetType,
    RelationshipType,
)
from threatlens.reasoning import (
    Confidence,
    ConfidenceBand,
    Finding,
    FindingCategory,
    InvestigationSummary,
    Severity,
)

_NOW = datetime(2024, 6, 1, tzinfo=UTC)
_SIZES = (1, 10, 50, 100, 500, 1000)

# Distinct-per-index IOC builders, cycled so every generator (network, hash,
# host, SIEM) fires. ``sha256`` is what exercises the YARA generator.
_BUILDERS: list[tuple[EntityType, FindingCategory, Callable[[int], str]]] = [
    (
        EntityType.IPV4,
        FindingCategory.MALICIOUS_INFRASTRUCTURE,
        lambda i: f"10.{i % 250}.0.{i % 250}",
    ),
    (EntityType.DOMAIN, FindingCategory.MALICIOUS_INFRASTRUCTURE, lambda i: f"evil{i}.example.net"),
    (EntityType.URL, FindingCategory.MALICIOUS_INFRASTRUCTURE, lambda i: f"http://evil{i}.test/p"),
    (EntityType.SHA256, FindingCategory.MALWARE, lambda i: f"{i:064x}"),
    (EntityType.PROCESS_NAME, FindingCategory.MALWARE, lambda i: f"proc{i}.exe"),
    (EntityType.REGISTRY_KEY, FindingCategory.MALWARE, lambda i: rf"HKLM\Software\Evil{i}"),
    (EntityType.POWERSHELL_COMMAND, FindingCategory.MALWARE, lambda i: f"Invoke-Thing{i}"),
]


def _finding(index: int) -> Finding:
    entity_type, category, make = _BUILDERS[index % len(_BUILDERS)]
    value = make(index)
    return Finding(
        id=f"fnd_{index:06d}",
        title=f"{entity_type.value}:{value}",
        categories=frozenset({category}),
        subject_type=entity_type,
        subject_value=value,
        severity=Severity.HIGH,
        confidence=Confidence(score=80, band=ConfidenceBand.HIGH),
        sources=["abuseipdb"],
        relationships=[
            AttributedRelationship(
                relationship=Relationship(
                    relationship=RelationshipType.USES,
                    target_type=RelationshipTargetType.ATTACK_PATTERN,
                    target_value="T1071",
                ),
                sources=["mitre_attack"],
            )
        ],
    )


def _summary(n: int) -> InvestigationSummary:
    findings = [_finding(i) for i in range(n)]
    return InvestigationSummary(
        entity_type=EntityType.IPV4,
        entity_value="10.0.0.1",
        posture=Severity.HIGH,
        overall_confidence=Confidence(score=80, band=ConfidenceBand.HIGH),
        findings=findings,
        engine_version="1.0",
        generated_at=_NOW,
    )


# --------------------------------------------------------------------------- #
# Timing & memory
# --------------------------------------------------------------------------- #


def _iterations(n: int) -> int:
    """Fewer repeats for the heavy sizes so the whole run stays quick."""
    return max(3, min(200, 2000 // n))


def _bench(fn: Callable[[], object], iterations: int) -> tuple[float, float]:
    fn()  # warm up
    samples = []
    for _ in range(iterations):
        start = perf_counter()
        fn()
        samples.append((perf_counter() - start) * 1e3)  # milliseconds
    return statistics.median(samples), statistics.fmean(samples)


def _peak_kib(fn: Callable[[], object]) -> float:
    tracemalloc.start()
    fn()
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return peak / 1024


def measure_scaling() -> list[dict[str, float]]:
    """Time and memory for ``generate`` across the requested investigation sizes."""
    rows: list[dict[str, float]] = []
    for n in _SIZES:
        summary = _summary(n)
        rules = len(generate(summary).artifacts)
        median_ms, mean_ms = _bench(lambda s=summary: generate(s), _iterations(n))
        peak = _peak_kib(lambda s=summary: generate(s))
        rows.append(
            {
                "findings": float(n),
                "rules": float(rules),
                "median_ms": median_ms,
                "mean_ms": mean_ms,
                "us_per_rule": (median_ms * 1e3 / rules) if rules else 0.0,
                "peak_kib": peak,
            }
        )
    return rows


def measure_per_generator(n: int = 1000) -> list[dict[str, object]]:
    """Per-generator time & rule count at the largest size (largest contributor)."""
    summary = _summary(n)
    rows: list[dict[str, object]] = []
    for gen in build_default_registry().generators:
        artifacts: list[DetectionArtifact] = list(gen.generate(summary))
        median_ms, _ = _bench(lambda g=gen: list(g.generate(summary)), _iterations(n))
        rows.append({"generator": gen.name, "rules": len(artifacts), "median_ms": median_ms})
    rows.sort(key=lambda r: r["median_ms"], reverse=True)  # type: ignore[arg-type,return-value]
    return rows


# --------------------------------------------------------------------------- #
# Report
# --------------------------------------------------------------------------- #


def main() -> None:
    print("Detection Engine — generation scaling (pure, offline)\n")
    print(f"{'findings':>9} {'rules':>7} {'median':>10} {'mean':>10} {'us/rule':>9} {'peakKiB':>9}")
    print("-" * 62)
    rows = measure_scaling()
    for r in rows:
        print(
            f"{int(r['findings']):>9} {int(r['rules']):>7} "
            f"{r['median_ms']:>8.3f}ms {r['mean_ms']:>8.3f}ms "
            f"{r['us_per_rule']:>9.2f} {r['peak_kib']:>9.1f}"
        )

    per_rule = [r["us_per_rule"] for r in rows if r["rules"]]
    if per_rule:
        spread = max(per_rule) / min(per_rule)
        verdict = "linear" if spread <= 3.0 else "super-linear (investigate)"
        print(f"\nper-rule cost spread across sizes: {spread:.2f}x  → {verdict}")

    print("\nPer-generator breakdown at 1000 findings (largest contributor first):")
    print(f"  {'generator':<12}  {'rules':>6}  {'median':>10}")
    print("  " + "-" * 32)
    for g in measure_per_generator():
        print(f"  {g['generator']:<12}  {g['rules']:>6}  {float(g['median_ms']):>8.3f}ms")


if __name__ == "__main__":
    main()
