"""The ``EntityDetector`` contract.

Each entity type is implemented as a detector that defines the four concerns
the architecture calls for — validation/detection (:meth:`matches`),
normalization (:meth:`normalize`), confidence (:meth:`confidence`), and routing
metadata (:meth:`routing`). Detectors are pure and synchronous: no network, no
AI, no shared state. The engine iterates registered detectors in priority order
rather than branching on type, so new types are added without touching existing
detection logic.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import ClassVar

from ...entities.models import RoutingMetadata
from ...entities.types import EntityType, ValidationStatus


@dataclass(frozen=True, slots=True)
class DetectionContext:
    """Immutable input passed to every detector for a single classification.

    ``raw`` is the original input (trimmed); ``normalized`` is the refanged,
    cleaned form detectors should inspect.
    """

    raw: str
    normalized: str


class EntityDetector(ABC):
    """Base class for all entity detectors.

    Subclasses set :attr:`entity_type` and :attr:`priority` and implement
    :meth:`matches` and :meth:`normalize`. ``priority`` orders detection: lower
    runs first, so the first matching detector wins as the primary result and
    later matches become ``possible_matches``.
    """

    entity_type: ClassVar[EntityType]
    priority: ClassVar[int]

    @abstractmethod
    def matches(self, ctx: DetectionContext) -> bool:
        """Return True if ``ctx.normalized`` is a valid instance of this type."""

    @abstractmethod
    def normalize(self, ctx: DetectionContext) -> str:
        """Return the canonical form. Only called when :meth:`matches` is True."""

    def confidence(self, ctx: DetectionContext) -> int:
        """Confidence 0-100 that this classification is correct.

        Defaults to 100 for deterministically-validated structural types;
        heuristic/soft-type detectors override with lower values.
        """
        return 100

    def validation(self, ctx: DetectionContext) -> ValidationStatus:
        """Validation state for the match. Defaults to ``VALID``."""
        return ValidationStatus.VALID

    def routing(self) -> RoutingMetadata:
        """Routing metadata placeholder (empty until Phase 1.2)."""
        return RoutingMetadata()
