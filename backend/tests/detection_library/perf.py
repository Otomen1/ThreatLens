"""Performance benchmark for the Detection Knowledge Library (Phase 4.6).

Pure, offline, CPU-only: measures library build (normalize + index), search, and
recommendation, plus recommendation scaling as the library grows to 1000 rules
(synthesized by cloning the seed). No network, no clock on the measured path.

Run: ``python tests/detection_library/perf.py`` (smoke-tested by test_perf_smoke).
"""

from __future__ import annotations

import statistics
from collections.abc import Callable
from time import perf_counter

from threatlens.detection_library import (
    DetectionLibrary,
    build_default_provider_registry,
    recommend,
)

from .corpus import SCENARIOS

_SIZES = (18, 100, 500, 1000)


def _bench(fn: Callable[[], object], iterations: int) -> float:
    fn()  # warm up
    samples = []
    for _ in range(iterations):
        start = perf_counter()
        fn()
        samples.append((perf_counter() - start) * 1e3)  # ms
    return statistics.median(samples)


def _library_of(size: int) -> DetectionLibrary:
    """Synthesize a library of ``size`` rules by cloning the seed corpus."""
    seed = build_default_provider_registry().all_rules()
    rules = []
    i = 0
    while len(rules) < size:
        base = seed[i % len(seed)]
        clone = base.model_copy(update={"id": f"{base.id}_{i}", "rule_id": f"{base.rule_id}-{i}"})
        rules.append(clone)
        i += 1
    return DetectionLibrary(tuple(rules))


def measure() -> dict[str, object]:
    registry = build_default_provider_registry()
    seed_library = DetectionLibrary(registry.all_rules())
    summary = SCENARIOS[4].summary  # multi_ioc — the heaviest profile

    build_ms = _bench(lambda: DetectionLibrary(registry.all_rules()), 200)
    search_ms = _bench(lambda: seed_library.search(technique="T1071"), 500)
    recommend_ms = _bench(lambda: recommend(summary, seed_library), 300)

    scaling = []
    for size in _SIZES:
        library = _library_of(size)
        ms = _bench(lambda lib=library: recommend(summary, lib), max(20, 2000 // size))
        scaling.append({"rules": size, "recommend_ms": ms, "us_per_rule": ms * 1e3 / size})

    return {
        "build_ms": build_ms,
        "search_ms": search_ms,
        "recommend_ms": recommend_ms,
        "scaling": scaling,
    }


def main() -> None:
    r = measure()
    print("Detection Knowledge Library — performance (pure, offline)\n")
    print(f"  build (normalize 18 rules + index) : {r['build_ms']:.3f} ms")
    print(f"  search (one technique query)       : {r['search_ms']:.4f} ms")
    print(f"  recommend (multi-IOC investigation): {r['recommend_ms']:.3f} ms\n")
    print(f"  {'rules':>6}  {'recommend':>12}  {'us/rule':>9}")
    print("  " + "-" * 32)
    scaling = r["scaling"]
    assert isinstance(scaling, list)
    for row in scaling:
        print(f"  {row['rules']:>6}  {row['recommend_ms']:>10.3f}ms  {row['us_per_rule']:>9.2f}")
    per_rule = [row["us_per_rule"] for row in scaling]
    spread = max(per_rule) / min(per_rule)
    print(
        f"\n  per-rule cost spread: {spread:.2f}x → {'linear' if spread <= 3 else 'super-linear'}"
    )


if __name__ == "__main__":
    main()
