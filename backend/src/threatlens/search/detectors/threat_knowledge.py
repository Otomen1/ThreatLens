"""Threat-knowledge detectors: threat actor and malware family.

The "softest" types: recognized by exact reference-data lookup (plus the
structural ``APT\\d+`` pattern for actors), with confidence reflecting that
names can collide with ordinary words. These are classified, never parsed, and
never inferred by an LLM (PHASE-0-ARCHITECTURE.md §27). Overlaps (a name that is
both an actor and a family) surface via ``possible_matches``.
"""

from __future__ import annotations

import re
from typing import ClassVar

from ...entities.reference import MALWARE_FAMILIES, THREAT_ACTORS
from ...entities.types import EntityType
from .base import DetectionContext, EntityDetector

_APT_RE = re.compile(r"APT-?\d{1,4}", re.IGNORECASE)


class ThreatActorDetector(EntityDetector):
    entity_type: ClassVar[EntityType] = EntityType.THREAT_ACTOR
    priority: ClassVar[int] = 130

    def matches(self, ctx: DetectionContext) -> bool:
        s = ctx.normalized
        return _APT_RE.fullmatch(s) is not None or s.lower() in THREAT_ACTORS

    def normalize(self, ctx: DetectionContext) -> str:
        canonical = THREAT_ACTORS.get(ctx.normalized.lower())
        if canonical is not None:
            return canonical
        # APT pattern not in the catalog: canonicalize spacing/case (APT29).
        return ctx.normalized.upper().replace("-", "")

    def confidence(self, ctx: DetectionContext) -> int:
        # The APT pattern is highly specific; named aliases are less certain.
        return 95 if _APT_RE.fullmatch(ctx.normalized) is not None else 85


class MalwareFamilyDetector(EntityDetector):
    entity_type: ClassVar[EntityType] = EntityType.MALWARE_FAMILY
    priority: ClassVar[int] = 140

    def matches(self, ctx: DetectionContext) -> bool:
        return ctx.normalized.lower() in MALWARE_FAMILIES

    def normalize(self, ctx: DetectionContext) -> str:
        return MALWARE_FAMILIES[ctx.normalized.lower()]

    def confidence(self, ctx: DetectionContext) -> int:
        return 80
