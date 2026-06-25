"""The Universal Search core. Phase 1.1 implements entity detection.

Exposes a process-wide default engine and a module-level :func:`detect` for the
common case. The engine and registry are also exported for callers that want to
build a customized detector set (e.g. tests).
"""

from __future__ import annotations

from ..entities.models import Entity
from .classifier import DetectionEngine, build_default_engine
from .registry import EntityRegistry

_default_engine: DetectionEngine = build_default_engine()


def detect(raw_input: str) -> Entity:
    """Classify arbitrary input into a normalized :class:`Entity`.

    Always returns a valid ``Entity``; unclassifiable input resolves to
    ``FREETEXT`` (multi-token) or ``UNKNOWN`` (single token).
    """
    return _default_engine.detect(raw_input)


__all__ = ["detect", "DetectionEngine", "EntityRegistry", "build_default_engine"]
