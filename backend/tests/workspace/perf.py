"""Performance baseline for the Workspace Platform (Phase 8.5).

Covers the five projections/operations Phase 8.5 asks to baseline:

* **Workspace load** (and save) — real disk I/O through
  :class:`~threatlens.workspace.storage.LocalFileStorage`, keyed by finding
  count.
* **Timeline projection** — :meth:`~threatlens.timeline.service.TimelineService.build`.
* **Graph projection** — :meth:`~threatlens.graph.service.GraphService.build`.
* **Report projection + JSON export** — :meth:`~threatlens.reporting.service.ReportService.build`
  followed by ``InvestigationReport.model_dump_json()``, since the export
  response body *is* that JSON.

A *baseline* measurement, not a scaling-law study like
``tests/correlation/perf.py``'s: Phase 8.5 froze these four subsystems'
contracts, and this exists to record representative timings for that freeze,
not to characterize asymptotic behavior. Still measured across a small range
of finding counts (5 -> 400, well past any realistic single investigation) so
an accidental super-linear regression in a future change would show up here
rather than going unnoticed.

Graph is benchmarked from ``investigation_summary``-derived findings only
(no ``correlation_summary``); observation-derived nodes/edges go through the
identical node/edge dedup-and-sort pipeline (see ``graph/engine.py``), so a
second, correlation-only scaling curve would not exercise any different cost
model — this keeps the harness genuinely minimal rather than doubling its
surface for no new signal.

Every operation is offline: local temp-directory file I/O for the workspace
persistence benchmark, pure in-memory computation for the other three. No
network, no AI, no external service.

Run the report::

    cd backend && python -m tests.workspace.perf

Exercised (without timing assertions) by ``test_perf_smoke.py`` so it cannot
bit-rot in CI.
"""

from __future__ import annotations

import statistics
import time
import tracemalloc
from collections.abc import Callable
from datetime import UTC, datetime
from functools import partial
from pathlib import Path
from tempfile import TemporaryDirectory
from uuid import uuid4

from threatlens.entities.types import EntityType
from threatlens.graph import GraphService
from threatlens.providers.aggregation import AttributedEvidence
from threatlens.providers.results import Evidence, EvidenceType
from threatlens.reasoning.models import (
    Confidence,
    ConfidenceBand,
    EvidenceDimension,
    EvidencePolarity,
    Finding,
    FindingCategory,
    InvestigationSummary,
    Severity,
    WeightedEvidence,
)
from threatlens.reporting import ReportService
from threatlens.timeline import TimelineService
from threatlens.workspace import (
    LocalFileStorage,
    SaveInvestigationRequest,
    WorkspaceInvestigation,
    WorkspaceService,
)

_SIZES = (5, 25, 100, 400)
_NOW = datetime(2024, 1, 1, tzinfo=UTC)
_CONFIDENCE = Confidence(score=80, band=ConfidenceBand.HIGH)


def _finding(i: int) -> Finding:
    evidence = WeightedEvidence(
        evidence=AttributedEvidence(
            evidence=Evidence(
                type=EvidenceType.CLASSIFICATION,
                summary=f"observation {i}",
                observed_at=_NOW,
            ),
            sources=["test_provider"],
        ),
        weight=1.0,
        polarity=EvidencePolarity.SUPPORTING,
        dimension=EvidenceDimension.REPUTATION,
    )
    return Finding(
        id=f"fnd_{i:05d}",
        title=f"Finding {i}",
        categories=frozenset({FindingCategory.MALICIOUS_INFRASTRUCTURE}),
        subject_type=EntityType.IPV4,
        subject_value=f"10.{i // 65536 % 256}.{i // 256 % 256}.{i % 256}",
        severity=Severity.HIGH,
        confidence=_CONFIDENCE,
        evidence=[evidence],
    )


def _summary(n: int) -> InvestigationSummary:
    return InvestigationSummary(
        entity_type=EntityType.IPV4,
        entity_value="8.8.8.8",
        posture=Severity.HIGH,
        overall_confidence=_CONFIDENCE,
        categories=frozenset(),
        findings=[_finding(i) for i in range(n)],
        engine_version="1.0",
        generated_at=_NOW,
    )


def _record(n: int) -> WorkspaceInvestigation:
    return WorkspaceInvestigation(
        id=uuid4(),
        title="Perf case",
        created_at=_NOW,
        updated_at=_NOW,
        investigation_type=EntityType.IPV4,
        investigation_summary=_summary(n),
    )


def _iterations(n: int) -> int:
    """Iteration budget for pure, in-memory projections."""
    return max(3, min(50, 1000 // n))


def _io_iterations(n: int) -> int:
    """Smaller budget for real-disk-I/O benchmarks — each call is a file write/read."""
    return max(3, min(20, 200 // n))


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


def measure_workspace_persistence() -> list[dict[str, float]]:
    """Time ``WorkspaceService.save()`` and ``.get()`` independently, through
    real :class:`LocalFileStorage` disk I/O, across growing finding counts."""
    rows: list[dict[str, float]] = []
    with TemporaryDirectory() as tmp:
        service = WorkspaceService(LocalFileStorage(Path(tmp)))
        for n in _SIZES:
            request = SaveInvestigationRequest(
                title="Perf case",
                investigation_type=EntityType.IPV4,
                investigation_summary=_summary(n),
            )
            save_run = partial(service.save, request, now=_NOW)
            save_median, save_mean = _bench(save_run, _io_iterations(n))

            seeded = service.save(request, now=_NOW)
            load_run = partial(service.get, seeded.id)
            load_median, load_mean = _bench(load_run, _io_iterations(n))
            peak = _peak_kib(load_run)

            rows.append(
                {
                    "findings": float(n),
                    "save_median_ms": save_median,
                    "save_mean_ms": save_mean,
                    "load_median_ms": load_median,
                    "load_mean_ms": load_mean,
                    "us_per_finding_save": save_median * 1e3 / n,
                    "us_per_finding_load": load_median * 1e3 / n,
                    "peak_kib": peak,
                }
            )
    return rows


def measure_timeline_projection() -> list[dict[str, float]]:
    """Time ``TimelineService.build()`` across growing finding counts."""
    service = TimelineService()
    rows: list[dict[str, float]] = []
    for n in _SIZES:
        rec = _record(n)
        run = partial(service.build, rec)
        events = len(service.build(rec).events)
        median_ms, mean_ms = _bench(run, _iterations(n))
        peak = _peak_kib(run)
        rows.append(
            {
                "findings": float(n),
                "events": float(events),
                "median_ms": median_ms,
                "mean_ms": mean_ms,
                "us_per_finding": median_ms * 1e3 / n,
                "peak_kib": peak,
            }
        )
    return rows


def measure_graph_projection() -> list[dict[str, float]]:
    """Time ``GraphService.build()`` across growing finding counts."""
    service = GraphService()
    rows: list[dict[str, float]] = []
    for n in _SIZES:
        rec = _record(n)
        run = partial(service.build, rec)
        nodes = len(service.build(rec).nodes)
        median_ms, mean_ms = _bench(run, _iterations(n))
        peak = _peak_kib(run)
        rows.append(
            {
                "findings": float(n),
                "nodes": float(nodes),
                "median_ms": median_ms,
                "mean_ms": mean_ms,
                "us_per_finding": median_ms * 1e3 / n,
                "peak_kib": peak,
            }
        )
    return rows


def measure_report_and_export() -> list[dict[str, float]]:
    """Time ``ReportService.build()`` and the export's ``model_dump_json()``
    independently, across growing finding counts."""
    service = ReportService(TimelineService(), GraphService())
    rows: list[dict[str, float]] = []
    for n in _SIZES:
        rec = _record(n)
        build_run = partial(service.build, rec)
        report = service.build(rec)
        export_run = report.model_dump_json
        build_median, build_mean = _bench(build_run, _iterations(n))
        export_median, export_mean = _bench(export_run, _iterations(n))
        peak = _peak_kib(build_run)
        rows.append(
            {
                "findings": float(n),
                "build_median_ms": build_median,
                "build_mean_ms": build_mean,
                "export_median_ms": export_median,
                "export_mean_ms": export_mean,
                "us_per_finding_build": build_median * 1e3 / n,
                "us_per_finding_export": export_median * 1e3 / n,
                "peak_kib": peak,
            }
        )
    return rows


def _verdict(values: list[float]) -> str:
    spread = max(values) / min(values) if min(values) > 0 else float("inf")
    return f"{spread:.2f}x -> {'linear' if spread <= 3.0 else 'super-linear (investigate)'}"


def main() -> None:
    print("Workspace Platform — performance baseline (Phase 8.5)\n")

    print("-- Workspace persistence: save() / get() through real LocalFileStorage I/O --\n")
    print(f"{'findings':>9} {'save med':>10} {'load med':>10} {'peakKiB':>9}")
    print("-" * 45)
    persistence_rows = measure_workspace_persistence()
    for r in persistence_rows:
        print(
            f"{int(r['findings']):>9} {r['save_median_ms']:>8.3f}ms "
            f"{r['load_median_ms']:>8.3f}ms {r['peak_kib']:>9.1f}"
        )
    print(
        "\nload per-finding cost spread: "
        f"{_verdict([r['us_per_finding_load'] for r in persistence_rows])}"
    )

    print("\n-- Timeline projection: TimelineService.build() --\n")
    print(f"{'findings':>9} {'events':>7} {'median':>10} {'peakKiB':>9}")
    print("-" * 40)
    timeline_rows = measure_timeline_projection()
    for r in timeline_rows:
        print(
            f"{int(r['findings']):>9} {int(r['events']):>7} "
            f"{r['median_ms']:>8.3f}ms {r['peak_kib']:>9.1f}"
        )
    print(f"\nper-finding cost spread: {_verdict([r['us_per_finding'] for r in timeline_rows])}")

    print("\n-- Graph projection: GraphService.build() --\n")
    print(f"{'findings':>9} {'nodes':>7} {'median':>10} {'peakKiB':>9}")
    print("-" * 40)
    graph_rows = measure_graph_projection()
    for r in graph_rows:
        print(
            f"{int(r['findings']):>9} {int(r['nodes']):>7} "
            f"{r['median_ms']:>8.3f}ms {r['peak_kib']:>9.1f}"
        )
    print(f"\nper-finding cost spread: {_verdict([r['us_per_finding'] for r in graph_rows])}")

    print("\n-- Report projection + JSON export --\n")
    print(f"{'findings':>9} {'build med':>11} {'export med':>12} {'peakKiB':>9}")
    print("-" * 48)
    report_rows = measure_report_and_export()
    for r in report_rows:
        print(
            f"{int(r['findings']):>9} {r['build_median_ms']:>9.3f}ms "
            f"{r['export_median_ms']:>10.3f}ms {r['peak_kib']:>9.1f}"
        )
    print(
        "\nbuild per-finding cost spread: "
        f"{_verdict([r['us_per_finding_build'] for r in report_rows])}"
    )
    print(
        "export per-finding cost spread: "
        f"{_verdict([r['us_per_finding_export'] for r in report_rows])}"
    )


if __name__ == "__main__":
    main()
