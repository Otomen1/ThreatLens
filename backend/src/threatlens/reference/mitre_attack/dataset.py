"""Offline loader and index for the MITRE ATT&CK STIX 2.1 bundle.

The provider works fully offline: this module reads a STIX bundle from disk (the
bundled curated subset by default, or the full official ``enterprise-attack.json``
when ``MITRE_ATTACK_DATASET_PATH`` points at it) and indexes it once. No network.

ATT&CK is distributed as STIX 2.1: techniques are ``attack-pattern`` objects,
mitigations ``course-of-action``, groups ``intrusion-set``, software ``malware``
or ``tool``, campaigns ``campaign`` — all tied together by ``relationship`` SROs.
The ATT&CK id (T/G/S/M/C…) lives in each object's ``external_references`` under
the ``mitre-attack`` source. This module resolves that graph into small, typed,
read-only views (:class:`Technique`, :class:`Group`, :class:`Software`) that the
provider normalizes into the canonical result. It holds no result/provider logic.
"""

from __future__ import annotations

import json
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

_MITRE_SOURCE = "mitre-attack"
_CAPEC_SOURCE = "capec"
_SOFTWARE_TYPES = frozenset({"malware", "tool"})


# --------------------------------------------------------------------------- #
# Typed views (what the provider normalizes; no STIX leaks past this module)
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class ExternalRef:
    """An external citation carried by an ATT&CK object."""

    title: str
    url: str
    description: str | None = None


@dataclass(frozen=True)
class NamedObject:
    """A lightweight reference to another ATT&CK object."""

    attack_id: str
    name: str
    url: str | None = None


@dataclass(frozen=True)
class SoftwareRef:
    """A reference to ATT&CK software, distinguishing malware from tooling."""

    attack_id: str
    name: str
    is_tool: bool
    url: str | None = None


@dataclass(frozen=True)
class Technique:
    """A resolved ATT&CK technique (or sub-technique)."""

    attack_id: str
    name: str
    description: str | None
    is_subtechnique: bool
    url: str | None
    tactics: tuple[str, ...] = ()
    platforms: tuple[str, ...] = ()
    permissions_required: tuple[str, ...] = ()
    data_sources: tuple[str, ...] = ()
    detection: str | None = None
    parent: NamedObject | None = None
    subtechniques: tuple[NamedObject, ...] = ()
    mitigations: tuple[NamedObject, ...] = ()
    groups: tuple[NamedObject, ...] = ()
    software: tuple[SoftwareRef, ...] = ()
    campaigns: tuple[NamedObject, ...] = ()
    capec: tuple[ExternalRef, ...] = ()
    references: tuple[ExternalRef, ...] = ()


@dataclass(frozen=True)
class Group:
    """A resolved ATT&CK group (adversary / intrusion set)."""

    attack_id: str
    name: str
    description: str | None
    url: str | None
    aliases: tuple[str, ...] = ()
    techniques: tuple[NamedObject, ...] = ()
    software: tuple[SoftwareRef, ...] = ()
    references: tuple[ExternalRef, ...] = ()


@dataclass(frozen=True)
class Software:
    """A resolved ATT&CK software entry (malware or tool)."""

    attack_id: str
    name: str
    description: str | None
    url: str | None
    is_tool: bool
    aliases: tuple[str, ...] = ()
    techniques: tuple[NamedObject, ...] = ()
    groups: tuple[NamedObject, ...] = ()
    references: tuple[ExternalRef, ...] = ()


# --------------------------------------------------------------------------- #
# Dataset
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class DatasetProvenance:
    """Version metadata describing the loaded dataset, for ReferenceMetadata."""

    version: str | None = None
    release_date: str | None = None
    last_updated: datetime | None = None


class MitreAttackDataset:
    """An indexed, read-only view over an ATT&CK STIX bundle.

    Built once (eagerly at provider construction) and queried per lookup. Views
    are resolved on demand so loading the full official bundle stays cheap.
    """

    def __init__(self, objects: Iterable[dict[str, Any]]) -> None:
        self._by_id: dict[str, dict[str, Any]] = {}
        self._attack_to_id: dict[str, str] = {}
        self._group_index: dict[str, str] = {}  # lowercased name/alias -> stix id
        self._software_index: dict[str, str] = {}  # lowercased name/alias -> stix id
        # adjacency keyed by (relationship_type, ref) -> the opposite refs
        self._targets: dict[tuple[str, str], list[str]] = defaultdict(list)
        self._sources: dict[tuple[str, str], list[str]] = defaultdict(list)
        self._provenance = DatasetProvenance()

        for obj in objects:
            self._ingest(obj)

    # --- construction helpers --------------------------------------------- #

    @classmethod
    def from_bundle(cls, bundle: dict[str, Any]) -> MitreAttackDataset:
        """Build a dataset from an in-memory STIX bundle dict."""
        objects = bundle.get("objects")
        if not isinstance(objects, list):
            raise ValueError("STIX bundle has no 'objects' array")
        return cls(obj for obj in objects if isinstance(obj, dict))

    @classmethod
    def from_file(cls, path: Path) -> MitreAttackDataset:
        """Load and index a STIX bundle from ``path`` (offline)."""
        with path.open(encoding="utf-8") as fh:
            bundle = json.load(fh)
        if not isinstance(bundle, dict):
            raise ValueError("STIX bundle root must be a JSON object")
        return cls.from_bundle(bundle)

    def _ingest(self, obj: dict[str, Any]) -> None:
        obj_type = obj.get("type")
        stix_id = obj.get("id")
        if not isinstance(obj_type, str) or not isinstance(stix_id, str):
            return

        if obj_type == "x-mitre-collection":
            self._provenance = _provenance_of(obj)
            return

        if obj_type == "relationship":
            rel = obj.get("relationship_type")
            src = obj.get("source_ref")
            dst = obj.get("target_ref")
            if isinstance(rel, str) and isinstance(src, str) and isinstance(dst, str):
                self._targets[(rel, src)].append(dst)
                self._sources[(rel, dst)].append(src)
            return

        self._by_id[stix_id] = obj
        attack_id = _attack_id(obj)
        if attack_id:
            self._attack_to_id[attack_id.upper()] = stix_id
        if obj_type == "intrusion-set":
            self._index_names(obj, self._group_index, stix_id, "aliases")
        elif obj_type in _SOFTWARE_TYPES:
            self._index_names(obj, self._software_index, stix_id, "x_mitre_aliases")

    @staticmethod
    def _index_names(
        obj: dict[str, Any], index: dict[str, str], stix_id: str, alias_field: str
    ) -> None:
        names = [obj.get("name"), *(_str_list(obj.get(alias_field)))]
        for name in names:
            if isinstance(name, str) and name.strip():
                index.setdefault(name.strip().lower(), stix_id)

    # --- provenance ------------------------------------------------------- #

    @property
    def provenance(self) -> DatasetProvenance:
        """Version/date metadata derived from the bundle's collection object."""
        return self._provenance

    # --- lookups ---------------------------------------------------------- #

    def technique(self, attack_id: str) -> Technique | None:
        """Resolve a technique by ATT&CK id (e.g. ``T1059`` or ``T1059.001``)."""
        obj = self._object_for(attack_id, "attack-pattern")
        return self._build_technique(obj) if obj is not None else None

    def group(self, name_or_alias: str) -> Group | None:
        """Resolve an ATT&CK group by name or alias (case-insensitive)."""
        stix_id = self._group_index.get(name_or_alias.strip().lower())
        obj = self._by_id.get(stix_id) if stix_id else None
        return self._build_group(obj) if obj is not None else None

    def software(self, name_or_alias: str) -> Software | None:
        """Resolve ATT&CK software by name or alias (case-insensitive)."""
        stix_id = self._software_index.get(name_or_alias.strip().lower())
        obj = self._by_id.get(stix_id) if stix_id else None
        return self._build_software(obj) if obj is not None else None

    # --- view builders ---------------------------------------------------- #

    def _object_for(self, attack_id: str, obj_type: str) -> dict[str, Any] | None:
        stix_id = self._attack_to_id.get(attack_id.strip().upper())
        obj = self._by_id.get(stix_id) if stix_id else None
        return obj if obj is not None and obj.get("type") == obj_type else None

    def _build_technique(self, obj: dict[str, Any]) -> Technique:
        stix_id = obj["id"]
        capec, references = _split_references(obj)
        parents = self._named_neighbors(self._targets, "subtechnique-of", stix_id, "attack-pattern")
        return Technique(
            attack_id=_attack_id(obj) or "",
            name=_text(obj.get("name")) or "",
            description=_text(obj.get("description")),
            is_subtechnique=bool(obj.get("x_mitre_is_subtechnique")),
            url=_attack_url(obj),
            tactics=tuple(_tactics(obj)),
            platforms=tuple(_str_list(obj.get("x_mitre_platforms"))),
            permissions_required=tuple(_str_list(obj.get("x_mitre_permissions_required"))),
            data_sources=tuple(_str_list(obj.get("x_mitre_data_sources"))),
            detection=_text(obj.get("x_mitre_detection")),
            parent=parents[0] if parents else None,
            subtechniques=tuple(
                self._named_neighbors(self._sources, "subtechnique-of", stix_id, "attack-pattern")
            ),
            mitigations=tuple(
                self._named_neighbors(self._sources, "mitigates", stix_id, "course-of-action")
            ),
            groups=tuple(self._named_neighbors(self._sources, "uses", stix_id, "intrusion-set")),
            software=tuple(self._software_neighbors(self._sources, "uses", stix_id)),
            campaigns=tuple(self._named_neighbors(self._sources, "uses", stix_id, "campaign")),
            capec=tuple(capec),
            references=tuple(references),
        )

    def _build_group(self, obj: dict[str, Any]) -> Group:
        stix_id = obj["id"]
        _, references = _split_references(obj)
        return Group(
            attack_id=_attack_id(obj) or "",
            name=_text(obj.get("name")) or "",
            description=_text(obj.get("description")),
            url=_attack_url(obj),
            aliases=tuple(_str_list(obj.get("aliases"))),
            techniques=tuple(
                self._named_neighbors(self._targets, "uses", stix_id, "attack-pattern")
            ),
            software=tuple(self._software_neighbors(self._targets, "uses", stix_id)),
            references=tuple(references),
        )

    def _build_software(self, obj: dict[str, Any]) -> Software:
        stix_id = obj["id"]
        _, references = _split_references(obj)
        return Software(
            attack_id=_attack_id(obj) or "",
            name=_text(obj.get("name")) or "",
            description=_text(obj.get("description")),
            url=_attack_url(obj),
            is_tool=obj.get("type") == "tool",
            aliases=tuple(_str_list(obj.get("x_mitre_aliases"))),
            techniques=tuple(
                self._named_neighbors(self._targets, "uses", stix_id, "attack-pattern")
            ),
            groups=tuple(self._named_neighbors(self._sources, "uses", stix_id, "intrusion-set")),
            references=tuple(references),
        )

    # --- relationship resolution ------------------------------------------ #

    def _neighbors(
        self, adjacency: dict[tuple[str, str], list[str]], rel: str, ref: str, obj_type: str
    ) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for neighbor in adjacency.get((rel, ref), ()):
            obj = self._by_id.get(neighbor)
            if obj is not None and obj.get("type") == obj_type:
                out.append(obj)
        return out

    def _named_neighbors(
        self, adjacency: dict[tuple[str, str], list[str]], rel: str, ref: str, obj_type: str
    ) -> list[NamedObject]:
        return [
            NamedObject(_attack_id(o) or "", _text(o.get("name")) or "", _attack_url(o))
            for o in self._neighbors(adjacency, rel, ref, obj_type)
        ]

    def _software_neighbors(
        self, adjacency: dict[tuple[str, str], list[str]], rel: str, ref: str
    ) -> list[SoftwareRef]:
        out: list[SoftwareRef] = []
        for obj_type in _SOFTWARE_TYPES:
            out.extend(
                SoftwareRef(
                    _attack_id(o) or "",
                    _text(o.get("name")) or "",
                    is_tool=o.get("type") == "tool",
                    url=_attack_url(o),
                )
                for o in self._neighbors(adjacency, rel, ref, obj_type)
            )
        return out


# --------------------------------------------------------------------------- #
# Module-level STIX helpers
# --------------------------------------------------------------------------- #


def _mitre_ref(obj: dict[str, Any]) -> dict[str, Any] | None:
    for ref in obj.get("external_references", []):
        if isinstance(ref, dict) and ref.get("source_name") == _MITRE_SOURCE:
            return ref
    return None


def _attack_id(obj: dict[str, Any]) -> str | None:
    ref = _mitre_ref(obj)
    external_id = ref.get("external_id") if ref else None
    return external_id if isinstance(external_id, str) and external_id else None


def _attack_url(obj: dict[str, Any]) -> str | None:
    ref = _mitre_ref(obj)
    url = ref.get("url") if ref else None
    return url if isinstance(url, str) and url else None


def _split_references(obj: dict[str, Any]) -> tuple[list[ExternalRef], list[ExternalRef]]:
    """Split external_references into (CAPEC refs, other cited refs)."""
    capec: list[ExternalRef] = []
    other: list[ExternalRef] = []
    for ref in obj.get("external_references", []):
        if not isinstance(ref, dict):
            continue
        source = ref.get("source_name")
        url = ref.get("url")
        if source == _MITRE_SOURCE or not isinstance(url, str) or not url:
            continue
        external_id = _text(ref.get("external_id"))
        description = _text(ref.get("description"))
        if source == _CAPEC_SOURCE:
            capec.append(ExternalRef(title=external_id or "CAPEC", url=url, description="CAPEC"))
        else:
            title = description or _text(source) or url
            other.append(ExternalRef(title=title, url=url, description=description))
    return capec, other


def _tactics(obj: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for phase in obj.get("kill_chain_phases", []):
        if not isinstance(phase, dict) or phase.get("kill_chain_name") != _MITRE_SOURCE:
            continue
        name = phase.get("phase_name")
        if isinstance(name, str) and name.strip():
            out.append(name.strip().replace("-", " ").title())
    return out


def _provenance_of(obj: dict[str, Any]) -> DatasetProvenance:
    version = _text(obj.get("x_mitre_version"))
    modified = _text(obj.get("modified")) or _text(obj.get("created"))
    last_updated = _parse_stix_time(modified)
    release_date = modified[:10] if modified else None
    return DatasetProvenance(version=version, release_date=release_date, last_updated=last_updated)


def _parse_stix_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _str_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item.strip() for item in value if isinstance(item, str) and item.strip()]
