"""Smoke test: the validation report generator runs and covers the corpus.

Keeps ``report.py`` exercised in CI (no timing assertions — latency figures are
environment-dependent) so the report cannot bit-rot alongside the corpus.
"""

from __future__ import annotations

from .corpus import CORPUS
from .harness import run_corpus
from .report import collect, generate_markdown


def test_report_collect_covers_every_case() -> None:
    stats = collect(run_corpus(CORPUS))
    assert stats["total"] == len(CORPUS)
    # A healthy corpus has no failures.
    assert stats["failures"] == {}


def test_report_markdown_has_required_sections() -> None:
    markdown = generate_markdown()
    for section in ("# ThreatLens", "## Summary", "## Benchmark", "## Distributions", "Total IOCs"):
        assert section in markdown
