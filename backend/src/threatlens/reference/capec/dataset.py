"""Offline loader and index for MITRE CAPEC data.

Loads a JSON file in the ThreatLens CAPEC format (or the bundled curated subset)
and indexes attack patterns by CAPEC-ID for O(1) lookup.

No network is ever touched here. Online refresh is supported by pointing
CAPEC_DATASET_PATH at a JSON file populated by an external tool.
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
class CapecAttackStep:
    """One step in the attack execution flow."""

    phase: str  # "Explore", "Experiment", or "Exploit"
    description: str
    step: int | None = None


@dataclass(frozen=True)
class CapecSkill:
    """A skill an attacker needs to execute the pattern."""

    level: str  # "Low", "Medium", "High"
    description: str | None = None


@dataclass(frozen=True)
class CapecRelatedPattern:
    """A relationship to another CAPEC entry."""

    capec_id: int
    nature: str  # "ChildOf", "ParentOf", "CanFollow", "CanPrecede", "PeerOf"


@dataclass(frozen=True)
class CapecReference:
    """An external reference attached to a CAPEC."""

    title: str
    url: str | None = None


@dataclass(frozen=True)
class DatasetProvenance:
    """Version metadata describing the loaded dataset."""

    version: str | None = None
    release_date: str | None = None
    last_updated: datetime | None = None


@dataclass(frozen=True)
class Capec:
    """A resolved CAPEC record ready for normalization."""

    id: int
    name: str
    description: str
    extended_description: str | None
    abstraction: str | None  # "Meta", "Standard", "Detailed"
    typical_severity: str | None
    likelihood_of_attack: str | None
    prerequisites: tuple[str, ...]
    skills_required: tuple[CapecSkill, ...]
    resources_required: tuple[str, ...]
    indicators: tuple[str, ...]
    execution_flow: tuple[CapecAttackStep, ...]
    mitigations: tuple[str, ...]
    related_weaknesses: tuple[int, ...]  # CWE numeric IDs
    related_attack_patterns: tuple[CapecRelatedPattern, ...]  # other CAPECs
    related_techniques: tuple[str, ...]  # ATT&CK technique IDs, e.g. "T1059"
    references: tuple[CapecReference, ...]

    @property
    def capec_id(self) -> str:
        """Canonical string identifier, e.g. 'CAPEC-66'."""
        return f"CAPEC-{self.id}"


# --------------------------------------------------------------------------- #
# Dataset
# --------------------------------------------------------------------------- #


class CapecDataset:
    """An indexed, read-only view over a CAPEC JSON dataset.

    Built once and queried per lookup. The bundled seed file covers a curated
    set of high-profile attack patterns that bridge CWE weaknesses and ATT&CK
    techniques for offline use. Full datasets load via CAPEC_DATASET_PATH.
    """

    def __init__(self, data: dict[str, Any]) -> None:
        self._index: dict[int, Capec] = {}
        meta = data.get("_meta", {})
        self._provenance = DatasetProvenance(
            version=_text(meta.get("version")),
            release_date=_text(meta.get("release_date")),
            last_updated=_parse_time(meta.get("release_date")),
        )
        for entry in data.get("attack_patterns", []):
            if isinstance(entry, dict):
                capec = _parse_capec(entry)
                if capec is not None:
                    self._index[capec.id] = capec

    @classmethod
    def from_file(cls, path: Path) -> CapecDataset:
        """Load and index a CAPEC JSON dataset from ``path`` (offline)."""
        with path.open(encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, dict):
            raise ValueError("CAPEC dataset root must be a JSON object")
        return cls(data)

    @property
    def provenance(self) -> DatasetProvenance:
        """Version/date metadata for the loaded dataset."""
        return self._provenance

    def lookup(self, capec_id: str) -> Capec | None:
        """Return the CAPEC record for ``capec_id`` (e.g. 'CAPEC-66'), or None.

        Accepts both 'CAPEC-66' and bare '66' (case-insensitive prefix).
        """
        key = capec_id.strip().upper()
        if key.startswith("CAPEC-"):
            key = key[6:]
        try:
            return self._index.get(int(key))
        except ValueError:
            return None

    def __len__(self) -> int:
        return len(self._index)


# --------------------------------------------------------------------------- #
# Parsing helpers (private)
# --------------------------------------------------------------------------- #


def _parse_capec(obj: dict[str, Any]) -> Capec | None:
    capec_id = obj.get("id")
    if not isinstance(capec_id, int):
        return None

    name = _text(obj.get("name")) or ""
    description = _text(obj.get("description")) or ""

    prerequisites = _str_tuple(obj.get("prerequisites"))
    resources = _str_tuple(obj.get("resources_required"))
    indicators = _str_tuple(obj.get("indicators"))
    mitigations = _str_tuple(obj.get("mitigations"))

    skills = tuple(
        s for s in (_parse_skill(x) for x in obj.get("skills_required", [])) if s is not None
    )
    flow = tuple(
        s for s in (_parse_step(x) for x in obj.get("execution_flow", [])) if s is not None
    )
    related = tuple(
        r
        for r in (_parse_related(x) for x in obj.get("related_attack_patterns", []))
        if r is not None
    )
    refs = tuple(
        r for r in (_parse_reference(x) for x in obj.get("references", [])) if r is not None
    )

    cwe_ids: list[int] = []
    seen_cwe: set[int] = set()
    for raw in obj.get("related_weaknesses", []):
        if isinstance(raw, int) and raw not in seen_cwe:
            seen_cwe.add(raw)
            cwe_ids.append(raw)

    techniques: list[str] = []
    seen_tech: set[str] = set()
    for raw in obj.get("related_techniques", []):
        tech = _text(raw)
        if tech:
            tech = tech.upper()
            if tech not in seen_tech:
                seen_tech.add(tech)
                techniques.append(tech)

    return Capec(
        id=capec_id,
        name=name,
        description=description,
        extended_description=_text(obj.get("extended_description")),
        abstraction=_text(obj.get("abstraction")),
        typical_severity=_text(obj.get("typical_severity")),
        likelihood_of_attack=_text(obj.get("likelihood_of_attack")),
        prerequisites=prerequisites,
        skills_required=skills,
        resources_required=resources,
        indicators=indicators,
        execution_flow=flow,
        mitigations=mitigations,
        related_weaknesses=tuple(cwe_ids),
        related_attack_patterns=related,
        related_techniques=tuple(techniques),
        references=refs,
    )


def _parse_skill(obj: Any) -> CapecSkill | None:
    if not isinstance(obj, dict):
        return None
    level = _text(obj.get("level"))
    if not level:
        return None
    return CapecSkill(level=level, description=_text(obj.get("description")))


def _parse_step(obj: Any) -> CapecAttackStep | None:
    if not isinstance(obj, dict):
        return None
    phase = _text(obj.get("phase"))
    desc = _text(obj.get("description"))
    if not phase or not desc:
        return None
    step = obj.get("step")
    return CapecAttackStep(
        phase=phase,
        description=desc,
        step=step if isinstance(step, int) else None,
    )


def _parse_related(obj: Any) -> CapecRelatedPattern | None:
    if not isinstance(obj, dict):
        return None
    capec_id = obj.get("capec_id")
    nature = _text(obj.get("nature"))
    if not isinstance(capec_id, int) or not nature:
        return None
    return CapecRelatedPattern(capec_id=capec_id, nature=nature)


def _parse_reference(obj: Any) -> CapecReference | None:
    if not isinstance(obj, dict):
        return None
    title = _text(obj.get("title"))
    if not title:
        return None
    return CapecReference(title=title, url=_text(obj.get("url")))


def _str_tuple(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(s for s in (_text(v) for v in value) if s is not None)


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
