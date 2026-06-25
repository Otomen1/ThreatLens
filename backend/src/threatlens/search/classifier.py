"""The detection engine: turns raw input into a normalized :class:`Entity`.

The engine refangs the input once, runs every registered detector over it, and
assembles the result: the highest-priority match becomes the primary entity and
any remaining matches are surfaced as ``possible_matches`` (transparent
ambiguity, never a silently-guessed single answer). Detector exceptions are
contained so one misbehaving detector cannot break classification.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..entities.models import Entity, EntityMatch, RoutingMetadata
from ..entities.types import EntityType, ValidationStatus
from .detectors import register_default_detectors
from .detectors.base import DetectionContext, EntityDetector
from .normalize import refang
from .registry import EntityRegistry


@dataclass(frozen=True, slots=True)
class _Match:
    """Internal per-detector result before assembly into an ``Entity``."""

    type: EntityType
    normalized_value: str
    confidence: int
    validation: ValidationStatus
    routing: RoutingMetadata


class DetectionEngine:
    """Classifies input by iterating registered detectors in priority order."""

    def __init__(self, registry: EntityRegistry) -> None:
        self._registry = registry

    def detect(self, raw_input: str) -> Entity:
        """Classify ``raw_input`` into an :class:`Entity` (never raises)."""
        raw = (raw_input or "").strip()
        normalized_input = refang(raw)
        ctx = DetectionContext(raw=raw, normalized=normalized_input)

        matches = [m for det in self._registry.detectors if (m := self._run(det, ctx))]
        if not matches:
            return self._fallback(raw, normalized_input)

        primary, *rest = matches
        possible = sorted(
            (EntityMatch(type=m.type, confidence=m.confidence) for m in rest),
            key=lambda m: m.confidence,
            reverse=True,
        )
        return Entity(
            type=primary.type,
            value=raw,
            normalized_value=primary.normalized_value,
            confidence=primary.confidence,
            validation=primary.validation,
            possible_matches=possible,
            routing=primary.routing,
        )

    @staticmethod
    def _run(detector: EntityDetector, ctx: DetectionContext) -> _Match | None:
        """Run one detector defensively; return its match or ``None``."""
        try:
            if not detector.matches(ctx):
                return None
            return _Match(
                type=detector.entity_type,
                normalized_value=detector.normalize(ctx),
                confidence=detector.confidence(ctx),
                validation=detector.validation(ctx),
                routing=detector.routing(),
            )
        except Exception:
            # A detector must never break classification; treat as non-match.
            return None

    @staticmethod
    def _fallback(raw: str, normalized: str) -> Entity:
        """Build the terminal result when no detector matches."""
        stripped = normalized.strip()
        is_freetext = len(stripped.split()) > 1
        return Entity(
            type=EntityType.FREETEXT if is_freetext else EntityType.UNKNOWN,
            value=raw,
            normalized_value=stripped,
            confidence=0,
            validation=ValidationStatus.UNVALIDATED,
            possible_matches=[],
            routing=RoutingMetadata(),
        )


def build_default_engine() -> DetectionEngine:
    """Construct an engine with all Phase 1.1 detectors registered."""
    registry = EntityRegistry()
    register_default_detectors(registry)
    return DetectionEngine(registry)
