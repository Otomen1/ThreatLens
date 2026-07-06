"""Performance benchmark for the Exposure Engine (Phase 5.4).

Measures ``ExposureService.investigate`` over a growing number of distinct
lookups (1 -> 100), each fanning out to three in-process fake providers (no
network — provider I/O is out of scope here and already benchmarked per-
provider by their own live-account latency, which this sandbox cannot
exercise; see the Phase 5.1-5.3 docs). Reports wall time, peak allocation,
and per-lookup amortised cost — i.e. the *framework's own* routing/fan-out/
merge overhead. Also measures cache effectiveness (cold vs warm, via the
same ``InMemoryExposureCache`` real providers use) and ``merge_findings``'s
own scaling in isolation.

Run the full report (module form — this file reuses ``fakes.py``/``corpus.py``
via relative imports, so it must run as a package module, not a bare script)::

    cd backend && python -m tests.exposure_validation.perf

The harness is exercised (without timing assertions) by ``test_perf_smoke.py``
so it cannot bit-rot in CI.
"""

from __future__ import annotations

import asyncio
import statistics
import time
import tracemalloc
from collections.abc import Callable

from threatlens.entities.models import Entity
from threatlens.entities.types import EntityType
from threatlens.exposure.cache import ExposureCache, InMemoryExposureCache
from threatlens.exposure.models import (
    ExposureAuthType,
    ExposureCapability,
    ExposureFinding,
    ExposureProviderMetadata,
)
from threatlens.exposure.provider import ExposureProvider
from threatlens.exposure.registry import ExposureRegistry
from threatlens.exposure.service import ExposureService
from threatlens.exposure.summary import merge_findings

from .corpus import _CATEGORY_BY_NAME
from .fakes import FakeExposureProvider, entity, ok_finding

_SIZES = (1, 10, 50, 100)


# --------------------------------------------------------------------------- #
# Scaling: ExposureService.investigate over N distinct lookups
# --------------------------------------------------------------------------- #


def _registry() -> ExposureRegistry:
    registry = ExposureRegistry()
    for name in ("censys", "greynoise", "shodan"):
        registry.register(
            FakeExposureProvider(name, finding=ok_finding(name, category=_CATEGORY_BY_NAME[name]))
        )
    return registry


async def _investigate_n(service: ExposureService, n: int) -> int:
    total_findings = 0
    for i in range(n):
        summary = await service.investigate(entity(f"192.0.2.{(i % 250) + 1}"))
        total_findings += len(summary.findings)
    return total_findings


def _iterations(n: int) -> int:
    return max(3, min(50, 500 // n))


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
    """Time and memory for ``investigate`` across a growing lookup count."""
    rows: list[dict[str, float]] = []
    for n in _SIZES:
        service = ExposureService(_registry())

        def run(n: int = n, service: ExposureService = service) -> int:
            return asyncio.run(_investigate_n(service, n))

        findings = run()
        median_ms, mean_ms = _bench(run, _iterations(n))
        peak = _peak_kib(run)
        rows.append(
            {
                "lookups": float(n),
                "findings": float(findings),
                "median_ms": median_ms,
                "mean_ms": mean_ms,
                "us_per_lookup": (median_ms * 1e3 / n),
                "peak_kib": peak,
            }
        )
    return rows


# --------------------------------------------------------------------------- #
# Cache effectiveness (cold vs warm, the real InMemoryExposureCache)
# --------------------------------------------------------------------------- #

_SIMULATED_MISS_COST_S = 0.002  # a deliberately-slow "real fetch" on a cache miss


class _CachingFakeProvider(ExposureProvider):
    """A fake provider that actually uses ``InMemoryExposureCache``.

    Mirrors every real provider's own cache-check -> miss -> store pattern
    (see ``ShodanProvider``/``CensysProvider``/``GreyNoiseProvider.lookup``)
    so the measured speedup reflects the shared cache abstraction, not a
    benchmark-only shortcut.
    """

    def __init__(self, cache: ExposureCache[ExposureFinding]) -> None:
        self._cache = cache
        self._meta = ExposureProviderMetadata(
            name="caching_fake",
            display_name="Caching Fake",
            supported_entity_types=frozenset({EntityType.IPV4}),
            capabilities=frozenset({ExposureCapability.OPEN_PORTS}),
            auth_type=ExposureAuthType.NONE,
        )

    @property
    def metadata(self) -> ExposureProviderMetadata:
        return self._meta

    async def lookup(self, entity: Entity) -> ExposureFinding:
        key = f"{entity.type.value}:{entity.value}"
        cached = self._cache.get(key)
        if cached is not None:
            return cached
        time.sleep(_SIMULATED_MISS_COST_S)  # simulates real provider I/O
        finding = ok_finding("caching_fake", entity_value=entity.value)
        self._cache.set(key, finding, ttl_seconds=3600.0)
        return finding


def measure_cache_effectiveness() -> dict[str, float]:
    """Cold (miss) vs warm (hit) latency for one repeated lookup."""
    provider = _CachingFakeProvider(InMemoryExposureCache())
    target = entity("192.0.2.50")

    t0 = time.perf_counter()
    asyncio.run(provider.lookup(target))
    cold_ms = (time.perf_counter() - t0) * 1e3

    t0 = time.perf_counter()
    asyncio.run(provider.lookup(target))
    warm_ms = (time.perf_counter() - t0) * 1e3

    return {
        "cold_ms": cold_ms,
        "warm_ms": warm_ms,
        "speedup": (cold_ms / warm_ms) if warm_ms > 0 else float("inf"),
    }


# --------------------------------------------------------------------------- #
# merge_findings in isolation (asymptotic behavior; real usage merges ~3)
# --------------------------------------------------------------------------- #


def measure_merge_cost() -> list[dict[str, float]]:
    """``merge_findings``'s own scaling, isolated from provider I/O entirely."""
    rows: list[dict[str, float]] = []
    for n in _SIZES:
        findings = [ok_finding(f"provider_{i}", entity_value="192.0.2.60") for i in range(n)]

        def run(findings: list[ExposureFinding] = findings) -> None:
            merge_findings(
                findings,
                entity_type=EntityType.IPV4,
                entity_value="192.0.2.60",
                framework_version="1.0",
            )

        median_ms, mean_ms = _bench(run, _iterations(n))
        peak = _peak_kib(run)
        rows.append(
            {
                "findings": float(n),
                "median_ms": median_ms,
                "mean_ms": mean_ms,
                "us_per_finding": (median_ms * 1e3 / n),
                "peak_kib": peak,
            }
        )
    return rows


# --------------------------------------------------------------------------- #
# Report
# --------------------------------------------------------------------------- #


def main() -> None:
    print("Exposure Engine — investigate() scaling (fake providers, in-process)\n")
    print(
        f"{'lookups':>9} {'findings':>9} {'median':>10} {'mean':>10} "
        f"{'us/lookup':>10} {'peakKiB':>9}"
    )
    print("-" * 65)
    rows = measure_scaling()
    for r in rows:
        print(
            f"{int(r['lookups']):>9} {int(r['findings']):>9} "
            f"{r['median_ms']:>8.3f}ms {r['mean_ms']:>8.3f}ms "
            f"{r['us_per_lookup']:>10.2f} {r['peak_kib']:>9.1f}"
        )

    # Direction matters here, unlike a monotonically-growing generator: a
    # smaller per-lookup cost at larger N means fixed per-call overhead
    # (asyncio.run's event-loop setup/teardown) is amortizing well, which is
    # the expected, healthy shape for this benchmark — not a regression.
    per_lookup = [r["us_per_lookup"] for r in rows]
    ratio = per_lookup[0] / per_lookup[-1]
    if ratio >= 1.0:
        verdict = f"amortizing ({ratio:.2f}x cheaper per lookup at scale — not a bottleneck)"
    else:
        verdict = f"cost grows {1 / ratio:.2f}x per lookup at scale (investigate)"
    n0, n1 = int(rows[0]["lookups"]), int(rows[-1]["lookups"])
    print(f"\nper-lookup cost trend, n={n0} -> n={n1}: {verdict}")

    cache = measure_cache_effectiveness()
    print("\nCache effectiveness (InMemoryExposureCache, one repeated lookup):")
    print(
        f"  cold (miss): {cache['cold_ms']:.3f}ms   "
        f"warm (hit): {cache['warm_ms']:.3f}ms   speedup: {cache['speedup']:.1f}x"
    )

    print("\nmerge_findings() scaling (isolated from provider I/O):")
    print(f"{'findings':>9} {'median':>10} {'mean':>10} {'us/finding':>11} {'peakKiB':>9}")
    print("-" * 55)
    for r in measure_merge_cost():
        print(
            f"{int(r['findings']):>9} {r['median_ms']:>8.3f}ms {r['mean_ms']:>8.3f}ms "
            f"{r['us_per_finding']:>11.2f} {r['peak_kib']:>9.1f}"
        )


if __name__ == "__main__":
    main()
