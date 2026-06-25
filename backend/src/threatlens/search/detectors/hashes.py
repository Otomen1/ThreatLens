"""File-hash detectors: MD5, SHA1, SHA256.

Hashes are recognized by exact hex length — the canonical, non-fragile approach
(a hash *is* a fixed-length hex string). Distinct types are kept separate
because they route to different intelligence sources later. Note the documented
ambiguity: a 32-hex GUID-without-dashes is indistinguishable from an MD5 and is
reported as MD5 (see PHASE-0-ARCHITECTURE.md §22).
"""

from __future__ import annotations

import re
from typing import ClassVar

from ...entities.types import EntityType
from .base import DetectionContext, EntityDetector

_HEX_RE = re.compile(r"[0-9a-fA-F]+")


class _HashDetector(EntityDetector):
    """Shared logic for fixed-length hex hashes."""

    length: ClassVar[int]

    def matches(self, ctx: DetectionContext) -> bool:
        s = ctx.normalized
        return len(s) == self.length and _HEX_RE.fullmatch(s) is not None

    def normalize(self, ctx: DetectionContext) -> str:
        return ctx.normalized.lower()


class Md5Detector(_HashDetector):
    entity_type: ClassVar[EntityType] = EntityType.MD5
    priority: ClassVar[int] = 50
    length: ClassVar[int] = 32


class Sha1Detector(_HashDetector):
    entity_type: ClassVar[EntityType] = EntityType.SHA1
    priority: ClassVar[int] = 51
    length: ClassVar[int] = 40


class Sha256Detector(_HashDetector):
    entity_type: ClassVar[EntityType] = EntityType.SHA256
    priority: ClassVar[int] = 52
    length: ClassVar[int] = 64
