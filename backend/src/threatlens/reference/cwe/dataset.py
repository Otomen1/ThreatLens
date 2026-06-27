"""Offline loader and index for MITRE CWE data.

Loads a JSON file in the ThreatLens CWE format (or the bundled curated subset)
and indexes weaknesses by CWE-ID for O(1) lookup.

No network is ever touched here. Online refresh is supported by pointing
CWE_DATASET_PATH at a JSON file populated by an external tool.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

# --------------------------------------------------------------------------- #
# Typed views (no raw JSON types leak past this module)
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class CweConsequence:
    """A common consequence of exploiting the weakness."""

    scope: str
    impact: str
    note: str | None = None


@dataclass(frozen=True)
class CweDetectionMethod:
    """A method for detecting the weakness."""

    method: str
    description: str | None = None


@dataclass(frozen=True)
class CweMitigation:
    """A mitigation or countermeasure for the weakness."""

    phase: str
    description: str


@dataclass(frozen=True)
class CweRelatedWeakness:
    """A relationship to another CWE entry."""

    cwe_id: int
    nature: str  # "ChildOf", "ParentOf", "PeerOf", etc.


@dataclass(frozen=True)
class CweReference:
    """An external reference attached to a CWE."""

    title: str
    url: str | None = None


@dataclass(frozen=True)
class DatasetProvenance:
    """Version metadata describing the loaded dataset."""

    version: str | None = None
    release_date: str | None = None
    last_updated: datetime | None = None


@dataclass(frozen=True)
class Cwe:
    """A resolved CWE record ready for normalization."""

    id: int
    name: str
    description: str
    extended_description: str | None
    likelihood_of_exploit: str | None
    applicable_platforms: tuple[str, ...]
    common_consequences: tuple[CweConsequence, ...]
    detection_methods: tuple[CweDetectionMethod, ...]
    mitigations: tuple[CweMitigation, ...]
    related_weaknesses: tuple[CweRelatedWeakness, ...]
    related_attack_patterns: tuple[int, ...]
    references: tuple[CweReference, ...]

    @property
    def cwe_id(self) -> str:
        """Canonical string identifier, e.g. 'CWE-79'."""
        return f"CWE-{self.id}"


# --------------------------------------------------------------------------- #
# Dataset
# --------------------------------------------------------------------------- #


class CweDataset:
    """An indexed, read-only view over a CWE JSON dataset.

    Built once at provider construction and queried per lookup. The bundled
    seed file covers a curated set of high-profile weaknesses for offline use.
    Full datasets can be loaded via CWE_DATASET_PATH.
    """

    def __init__(self, data: dict[str, Any]) -> None:
        self._index: dict[int, Cwe] = {}
        meta = data.get("_meta", {})
        self._provenance = DatasetProvenance(
            version=_text(meta.get("version")),
            release_date=_text(meta.get("release_date")),
            last_updated=_parse_time(meta.get("release_date")),
        )
        for entry in data.get("weaknesses", []):
            if isinstance(entry, dict):
                cwe = _parse_cwe(entry)
                if cwe is not None:
                    self._index[cwe.id] = cwe

    @classmethod
    def from_file(cls, path: Path) -> CweDataset:
        """Load and index a CWE JSON dataset from ``path`` (offline)."""
        with path.open(encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, dict):
            raise ValueError("CWE dataset root must be a JSON object")
        return cls(data)

    @property
    def provenance(self) -> DatasetProvenance:
        """Version/date metadata for the loaded dataset."""
        return self._provenance

    def lookup(self, cwe_id: str) -> Cwe | None:
        """Return the CWE record for ``cwe_id`` (e.g. 'CWE-79'), or None.

        Accepts both 'CWE-79' and bare '79' (case-insensitive prefix).
        """
        key = cwe_id.strip().upper()
        if key.startswith("CWE-"):
            key = key[4:]
        try:
            return self._index.get(int(key))
        except ValueError:
            return None

    def __len__(self) -> int:
        return len(self._index)


# --------------------------------------------------------------------------- #
# Parsing helpers (private)
# --------------------------------------------------------------------------- #


def _parse_cwe(obj: dict[str, Any]) -> Cwe | None:
    cwe_id = obj.get("id")
    if not isinstance(cwe_id, int):
        return None

    name = _text(obj.get("name")) or ""
    description = _text(obj.get("description")) or ""
    extended = _text(obj.get("extended_description"))
    likelihood = _text(obj.get("likelihood_of_exploit"))

    platforms = tuple(
        s for s in obj.get("applicable_platforms", []) if isinstance(s, str) and s.strip()
    )
    consequences = tuple(_parse_consequence(c) for c in obj.get("common_consequences", []))
    consequences = tuple(c for c in consequences if c is not None)
    detection = tuple(_parse_detection(d) for d in obj.get("detection_methods", []))
    detection = tuple(d for d in detection if d is not None)
    mitigations = tuple(_parse_mitigation(m) for m in obj.get("mitigations", []))
    mitigations = tuple(m for m in mitigations if m is not None)
    related = tuple(_parse_related(r) for r in obj.get("related_weaknesses", []))
    related = tuple(r for r in related if r is not None)

    capec_ids: list[int] = []
    seen_capec: set[int] = set()
    for raw in obj.get("related_attack_patterns", []):
        if isinstance(raw, int) and raw not in seen_capec:
            seen_capec.add(raw)
            capec_ids.append(raw)

    refs = tuple(_parse_reference(r) for r in obj.get("references", []))
    refs = tuple(r for r in refs if r is not None)

    return Cwe(
        id=cwe_id,
        name=name,
        description=description,
        extended_description=extended,
        likelihood_of_exploit=likelihood,
        applicable_platforms=platforms,
        common_consequences=consequences,
        detection_methods=detection,
        mitigations=mitigations,
        related_weaknesses=related,
        related_attack_patterns=tuple(capec_ids),
        references=refs,
    )


def _parse_consequence(obj: Any) -> CweConsequence | None:
    if not isinstance(obj, dict):
        return None
    scope = _text(obj.get("scope"))
    impact = _text(obj.get("impact"))
    if not scope or not impact:
        return None
    return CweConsequence(scope=scope, impact=impact, note=_text(obj.get("note")))


def _parse_detection(obj: Any) -> CweDetectionMethod | None:
    if not isinstance(obj, dict):
        return None
    method = _text(obj.get("method"))
    if not method:
        return None
    return CweDetectionMethod(method=method, description=_text(obj.get("description")))


def _parse_mitigation(obj: Any) -> CweMitigation | None:
    if not isinstance(obj, dict):
        return None
    phase = _text(obj.get("phase"))
    desc = _text(obj.get("description"))
    if not phase or not desc:
        return None
    return CweMitigation(phase=phase, description=desc)


def _parse_related(obj: Any) -> CweRelatedWeakness | None:
    if not isinstance(obj, dict):
        return None
    cwe_id = obj.get("cwe_id")
    nature = _text(obj.get("nature"))
    if not isinstance(cwe_id, int) or not nature:
        return None
    return CweRelatedWeakness(cwe_id=cwe_id, nature=nature)


def _parse_reference(obj: Any) -> CweReference | None:
    if not isinstance(obj, dict):
        return None
    title = _text(obj.get("title"))
    if not title:
        return None
    return CweReference(title=title, url=_text(obj.get("url")))


def _text(value: Any) -> str | None:
    if value is None:
        return None
    s = str(value).strip()
    return s or None


def _parse_time(value: Any) -> datetime | None:
    text = _text(value)
    if not text:
        return None
    for fmt in ("%Y.%m.%d", "%Y-%m-%d", "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    return None
