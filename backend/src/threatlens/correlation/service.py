"""The Correlation service — a thin, deterministic wrapper over the engine.

Mirrors ``exposure/service.py`` / ``detection`` orchestration: holds a rule
registry and exposes ``correlate(summary)``. Pure and side-effect-free — it
never mutates the input ``InvestigationSummary`` and never touches the network,
an AI model, or the wall clock.
"""

from __future__ import annotations

from ..reasoning.models import InvestigationSummary
from .engine import correlate
from .models import CorrelationSummary
from .registry import CorrelationRegistry, build_default_registry


class CorrelationService:
    """Runs the correlation rule registry over one investigation."""

    def __init__(self, registry: CorrelationRegistry | None = None) -> None:
        self._registry = registry if registry is not None else build_default_registry()

    @property
    def registry(self) -> CorrelationRegistry:
        """The rule registry this service runs (read-only access for callers)."""
        return self._registry

    def correlate(self, summary: InvestigationSummary) -> CorrelationSummary:
        """Produce a :class:`CorrelationSummary` for ``summary`` (never mutates it)."""
        return correlate(summary, registry=self._registry)
