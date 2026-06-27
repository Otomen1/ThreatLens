"""Structured-identifier detectors: CVE, CWE, CAPEC, MITRE technique, registry key.

All are deterministically recognizable by well-defined patterns/prefixes,
so they validate strictly and normalize to a canonical form.
"""

from __future__ import annotations

import re
from typing import ClassVar

from ...entities.types import EntityType
from .base import DetectionContext, EntityDetector

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
_CWE_RE = re.compile(r"CWE-\d+", re.IGNORECASE)
_CAPEC_RE = re.compile(r"CAPEC-\d+", re.IGNORECASE)
# ATT&CK techniques and sub-techniques (Txxxx / Txxxx.yyy); tactics (TAxxxx)
# are intentionally out of scope for Phase 1.1.
_MITRE_RE = re.compile(r"T\d{4}(?:\.\d{3})?", re.IGNORECASE)

# Registry hive abbreviations -> canonical full names.
_HIVE_ALIASES = {
    "HKLM": "HKEY_LOCAL_MACHINE",
    "HKCU": "HKEY_CURRENT_USER",
    "HKCR": "HKEY_CLASSES_ROOT",
    "HKU": "HKEY_USERS",
    "HKCC": "HKEY_CURRENT_CONFIG",
}
_HIVE_FULL = frozenset(_HIVE_ALIASES.values())


class CveDetector(EntityDetector):
    entity_type: ClassVar[EntityType] = EntityType.CVE
    priority: ClassVar[int] = 60

    def matches(self, ctx: DetectionContext) -> bool:
        return _CVE_RE.fullmatch(ctx.normalized) is not None

    def normalize(self, ctx: DetectionContext) -> str:
        return ctx.normalized.upper()


class CweDetector(EntityDetector):
    entity_type: ClassVar[EntityType] = EntityType.CWE
    priority: ClassVar[int] = 65

    def matches(self, ctx: DetectionContext) -> bool:
        return _CWE_RE.fullmatch(ctx.normalized) is not None

    def normalize(self, ctx: DetectionContext) -> str:
        return ctx.normalized.upper()


class CapecDetector(EntityDetector):
    entity_type: ClassVar[EntityType] = EntityType.CAPEC
    priority: ClassVar[int] = 67

    def matches(self, ctx: DetectionContext) -> bool:
        return _CAPEC_RE.fullmatch(ctx.normalized) is not None

    def normalize(self, ctx: DetectionContext) -> str:
        return ctx.normalized.upper()


class MitreTechniqueDetector(EntityDetector):
    entity_type: ClassVar[EntityType] = EntityType.MITRE_TECHNIQUE
    priority: ClassVar[int] = 70

    def matches(self, ctx: DetectionContext) -> bool:
        return _MITRE_RE.fullmatch(ctx.normalized) is not None

    def normalize(self, ctx: DetectionContext) -> str:
        return ctx.normalized.upper()


class RegistryKeyDetector(EntityDetector):
    entity_type: ClassVar[EntityType] = EntityType.REGISTRY_KEY
    priority: ClassVar[int] = 80

    def _split(self, ctx: DetectionContext) -> tuple[str, str] | None:
        s = ctx.normalized
        if "\\" not in s:
            return None
        head, _, rest = s.partition("\\")
        head_up = head.upper()
        if head_up in _HIVE_ALIASES or head_up in _HIVE_FULL:
            return head_up, rest
        return None

    def matches(self, ctx: DetectionContext) -> bool:
        return self._split(ctx) is not None

    def normalize(self, ctx: DetectionContext) -> str:
        split = self._split(ctx)
        assert split is not None
        head_up, rest = split
        full = _HIVE_ALIASES.get(head_up, head_up)
        return f"{full}\\{rest}" if rest else full
