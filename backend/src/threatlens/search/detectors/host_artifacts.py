"""Host-artifact detectors: process name, PowerShell command, Windows API.

These mix structural recognition with curated reference data. A process is any
bare executable filename (confidence boosted if it is a known binary); a
PowerShell command is a ``Verb-Noun`` with an approved verb (boosted if a known
cmdlet); a Windows API is a known function name or a conservative native
(``Nt``/``Zw``/``Rtl``) heuristic.
"""

from __future__ import annotations

import re
from typing import ClassVar

from ...entities.reference import (
    APPROVED_VERBS,
    KNOWN_CMDLETS,
    KNOWN_PROCESSES,
    WINDOWS_APIS,
)
from ...entities.types import EntityType
from .base import DetectionContext, EntityDetector

# Executable / script extensions treated as process names. Deliberately excludes
# ".com" to avoid colliding with the .com TLD (handled by the domain detector).
_EXEC_EXTENSIONS = frozenset(
    (
        "exe",
        "dll",
        "sys",
        "scr",
        "bat",
        "cmd",
        "ps1",
        "psm1",
        "vbs",
        "vbe",
        "js",
        "jse",
        "wsf",
        "wsh",
        "hta",
        "msi",
        "msp",
        "cpl",
        "pif",
        "scf",
        "lnk",
    )
)
_PROCESS_RE = re.compile(r"[A-Za-z0-9_.\-]+\.([A-Za-z0-9]+)")
_POWERSHELL_RE = re.compile(r"([A-Za-z]+)-([A-Za-z][A-Za-z0-9]*)")
# Native API heuristic: Nt/Zw/Rtl prefix followed by a CamelCase name.
_NATIVE_API_RE = re.compile(r"(?:Nt|Zw|Rtl)[A-Z][A-Za-z0-9]+")


class ProcessNameDetector(EntityDetector):
    entity_type: ClassVar[EntityType] = EntityType.PROCESS_NAME
    priority: ClassVar[int] = 100

    def _name(self, ctx: DetectionContext) -> str | None:
        s = ctx.normalized
        if "/" in s or "\\" in s:  # a path, not a bare process name
            return None
        m = _PROCESS_RE.fullmatch(s)
        if m is None or m.group(1).lower() not in _EXEC_EXTENSIONS:
            return None
        return s

    def matches(self, ctx: DetectionContext) -> bool:
        return self._name(ctx) is not None

    def normalize(self, ctx: DetectionContext) -> str:
        return ctx.normalized.lower()

    def confidence(self, ctx: DetectionContext) -> int:
        return 100 if ctx.normalized.lower() in KNOWN_PROCESSES else 70


class PowerShellCommandDetector(EntityDetector):
    entity_type: ClassVar[EntityType] = EntityType.POWERSHELL_COMMAND
    priority: ClassVar[int] = 110

    def _parts(self, ctx: DetectionContext) -> tuple[str, str] | None:
        m = _POWERSHELL_RE.fullmatch(ctx.normalized)
        if m is None or m.group(1).lower() not in APPROVED_VERBS:
            return None
        return m.group(1), m.group(2)

    def matches(self, ctx: DetectionContext) -> bool:
        return self._parts(ctx) is not None

    def normalize(self, ctx: DetectionContext) -> str:
        canonical = KNOWN_CMDLETS.get(ctx.normalized.lower())
        if canonical is not None:
            return canonical
        parts = self._parts(ctx)
        assert parts is not None
        verb, noun = parts
        return f"{verb.capitalize()}-{noun[:1].upper()}{noun[1:]}"

    def confidence(self, ctx: DetectionContext) -> int:
        return 95 if ctx.normalized.lower() in KNOWN_CMDLETS else 85


class WindowsApiDetector(EntityDetector):
    entity_type: ClassVar[EntityType] = EntityType.WINDOWS_API
    priority: ClassVar[int] = 120

    def matches(self, ctx: DetectionContext) -> bool:
        s = ctx.normalized
        return s.lower() in WINDOWS_APIS or _NATIVE_API_RE.fullmatch(s) is not None

    def normalize(self, ctx: DetectionContext) -> str:
        return WINDOWS_APIS.get(ctx.normalized.lower(), ctx.normalized)

    def confidence(self, ctx: DetectionContext) -> int:
        return 95 if ctx.normalized.lower() in WINDOWS_APIS else 70
