"""Extract supported IOCs from free-form analyst text."""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

from ..entities.models import Entity
from ..entities.types import EntityType
from .normalize import refang

MAX_BATCH_IOCS = 20

IOC_TYPES = frozenset(
    {
        EntityType.IPV4,
        EntityType.IPV6,
        EntityType.DOMAIN,
        EntityType.URL,
        EntityType.EMAIL,
        EntityType.MD5,
        EntityType.SHA1,
        EntityType.SHA256,
    }
)

# Ordered from most-specific to least-specific. Matches are de-overlapped so a
# URL is one IOC, rather than also producing its host as a separate domain.
_CANDIDATE_PATTERNS = (
    re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE),
    re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63}", re.IGNORECASE),
    re.compile(r"(?<![A-F0-9])[A-F0-9]{64}(?![A-F0-9])", re.IGNORECASE),
    re.compile(r"(?<![A-F0-9])[A-F0-9]{40}(?![A-F0-9])", re.IGNORECASE),
    re.compile(r"(?<![A-F0-9])[A-F0-9]{32}(?![A-F0-9])", re.IGNORECASE),
    re.compile(r"(?<![0-9A-F:])(?:[0-9A-F]{0,4}:){2,7}[0-9A-F]{0,4}(?![0-9A-F:])", re.IGNORECASE),
    re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])"),
    re.compile(r"(?<![\w.-])(?:[A-Z0-9-]+\.)+[A-Z]{2,63}(?![\w.-])", re.IGNORECASE),
)
_TRAILING_PUNCTUATION = ".,;:!?)]}"


class BatchIocLimitExceeded(ValueError):
    """Raised when a paste contains more IOCs than one batch may process."""


@dataclass(frozen=True, slots=True)
class IocExtractionReport:
    """Extraction result plus transparent de-duplication/validation counts."""

    entities: tuple[Entity, ...]
    candidates: int
    duplicates: int
    invalid: int


def extract_iocs(raw_text: str, *, detector: Callable[[str], Entity]) -> list[Entity]:
    """Return distinct supported IOC entities in first-seen order.

    Labels and prose are ignored because only shaped IOC candidates are passed
    to the existing detector. ``detector`` is injected to keep this utility
    straightforward to test and to ensure one source of type normalization.
    """
    return list(extract_ioc_report(raw_text, detector=detector).entities)


def extract_ioc_report(raw_text: str, *, detector: Callable[[str], Entity]) -> IocExtractionReport:
    """Extract IOCs and report only shaped invalid/duplicate candidates."""
    text = refang(raw_text)
    candidates: list[tuple[int, str]] = []
    occupied: list[tuple[int, int]] = []
    for pattern in _CANDIDATE_PATTERNS:
        for match in pattern.finditer(text):
            start, end = match.span()
            if any(start < used_end and end > used_start for used_start, used_end in occupied):
                continue
            candidate = match.group().rstrip(_TRAILING_PUNCTUATION)
            if candidate:
                candidates.append((start, candidate))
                occupied.append((start, end))

    entities: list[Entity] = []
    seen: set[tuple[EntityType, str]] = set()
    duplicates = 0
    invalid = 0
    for _, candidate in sorted(candidates, key=lambda item: item[0]):
        entity = detector(candidate)
        if entity.type not in IOC_TYPES:
            invalid += 1
            continue
        key = (entity.type, entity.normalized_value)
        if key in seen:
            duplicates += 1
            continue
        seen.add(key)
        entities.append(entity)
        if len(entities) > MAX_BATCH_IOCS:
            raise BatchIocLimitExceeded(f"A batch can contain at most {MAX_BATCH_IOCS} IOCs.")
    return IocExtractionReport(
        entities=tuple(entities),
        candidates=len(candidates),
        duplicates=duplicates,
        invalid=invalid,
    )
