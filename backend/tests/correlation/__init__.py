"""Offline tests for the Investigation Correlation Engine (Phase 7.0).

Zero network, zero providers, zero AI — the engine is pure and deterministic,
so every test builds a synthetic ``InvestigationSummary`` and asserts against
the ``CorrelationSummary`` it produces. Covers models, each seed rule,
registry, engine determinism/identity/ordering, aggregation, the service, the
API endpoint, a byte-stable golden snapshot, and a perf smoke.
"""

from __future__ import annotations
