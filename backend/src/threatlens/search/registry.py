"""The entity-detector registry.

A small, explicit container that holds detector instances ordered by priority.
It is the extension seam: registering a new detector is all it takes to teach
the engine a new entity type. Kept free of global mutable state so tests can
build isolated registries.
"""

from __future__ import annotations

from .detectors.base import EntityDetector


class EntityRegistry:
    """Holds detectors sorted by ascending priority."""

    def __init__(self) -> None:
        self._detectors: list[EntityDetector] = []

    def register(self, detector: EntityDetector) -> None:
        """Add a detector, keeping the collection ordered by priority."""
        self._detectors.append(detector)
        self._detectors.sort(key=lambda d: d.priority)

    @property
    def detectors(self) -> tuple[EntityDetector, ...]:
        """Registered detectors in priority order (lowest first)."""
        return tuple(self._detectors)
