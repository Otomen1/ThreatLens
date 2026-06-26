"""MITRE ATT&CK reference provider — the first concrete knowledge provider.

Resolves a detected entity against an offline ATT&CK STIX bundle and normalizes
the structured knowledge into the *shared* canonical
:class:`~threatlens.providers.results.IntelligenceResult` — references,
relationships, evidence, and metadata, but never reputation (reference providers
do not assess maliciousness). The future combined "ThreatLens Intelligence
Document" merges this through the existing ``providers.aggregate``.

It serves three entity types from one dataset:

* ``MITRE_TECHNIQUE`` → an ATT&CK technique / sub-technique (the rich blueprint).
* ``THREAT_ACTOR``    → an ATT&CK group (``intrusion-set``).
* ``MALWARE_FAMILY``  → ATT&CK software (``malware`` / ``tool``).

This is the reference implementation for all future knowledge providers (NVD,
CWE, CAPEC): a ``dataset`` module for offline loading/indexing, a provider that
maps typed views onto the canonical result, and a bundled seed dataset so it
works out of the box. See ``dataset.py`` for the STIX details.
"""

from __future__ import annotations

import os
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ...entities.models import Entity
from ...entities.types import EntityType
from ...providers.results import (
    Evidence,
    EvidenceType,
    IntelligenceResult,
    Reference,
    Relationship,
    RelationshipTargetType,
    RelationshipType,
    ResultStatus,
)
from ..base import ReferenceProvider
from ..models import ReferenceMetadata
from ..types import ReferenceCapability
from .dataset import (
    DatasetProvenance,
    ExternalRef,
    Group,
    MitreAttackDataset,
    Software,
    SoftwareRef,
    Technique,
)

_NAME = "mitre_attack"
_DISPLAY = "MITRE ATT&CK"
_SOURCE_URL = "https://attack.mitre.org"
_PRIORITY = 50
_DATASET_ENV = "MITRE_ATTACK_DATASET_PATH"
_BUNDLED_DATASET = Path(__file__).resolve().parent / "data" / "enterprise-attack-sample.json"

_SUPPORTED = frozenset(
    {EntityType.MITRE_TECHNIQUE, EntityType.THREAT_ACTOR, EntityType.MALWARE_FAMILY}
)
_CAPABILITIES = frozenset(
    {
        ReferenceCapability.TECHNIQUE,
        ReferenceCapability.TACTIC,
        ReferenceCapability.GROUP,
        ReferenceCapability.SOFTWARE,
        ReferenceCapability.CROSS_REFERENCE,
    }
)


class MitreAttackProvider(ReferenceProvider):
    """Looks entities up against an offline MITRE ATT&CK dataset."""

    def __init__(
        self,
        *,
        dataset: MitreAttackDataset | None = None,
        dataset_path: Path | None = None,
        enabled: bool = True,
    ) -> None:
        self._enabled = enabled
        self._load_error: str | None = None
        if dataset is not None:
            self._dataset: MitreAttackDataset | None = dataset
            return
        path = _resolve_dataset_path(dataset_path)
        try:
            self._dataset = MitreAttackDataset.from_file(path)
        except (OSError, ValueError) as exc:
            self._dataset = None
            self._load_error = f"could not load MITRE ATT&CK dataset from {path}: {exc}"

    @property
    def metadata(self) -> ReferenceMetadata:
        prov = self._dataset.provenance if self._dataset else DatasetProvenance()
        return ReferenceMetadata(
            name=_NAME,
            display_name=_DISPLAY,
            supported_entity_types=_SUPPORTED,
            capabilities=_CAPABILITIES,
            priority=_PRIORITY,
            enabled=self._enabled,
            provider_version="0.1.0",
            dataset_version=prov.version,
            release_date=prov.release_date,
            source_url=_SOURCE_URL,
            offline=True,
            last_updated=prov.last_updated,
        )

    async def lookup(self, entity: Entity) -> IntelligenceResult:
        """Resolve ``entity`` against the dataset and normalize it (never raises)."""
        if not self.supports(entity.type):
            return self._unsupported(entity.type, entity.value)
        if self._dataset is None:
            return self._fail(
                entity,
                ResultStatus.ERROR,
                "MITRE ATT&CK dataset unavailable",
                detail=self._load_error,
            )

        key = entity.normalized_value or entity.value
        if entity.type is EntityType.MITRE_TECHNIQUE:
            technique = self._dataset.technique(key)
            if technique is None:
                return self._not_found(entity.type, entity.value)
            return self._technique_result(entity.value, technique)
        if entity.type is EntityType.THREAT_ACTOR:
            group = self._dataset.group(key)
            if group is None:
                return self._not_found(entity.type, entity.value)
            return self._group_result(entity.value, group)
        # MALWARE_FAMILY (the only remaining supported type)
        software = self._dataset.software(key)
        if software is None:
            return self._not_found(entity.type, entity.value)
        return self._software_result(entity.value, software)

    async def normalize(self, raw: Any) -> IntelligenceResult:
        """Map a resolved dataset view into a canonical result (no entity needed)."""
        if isinstance(raw, Technique):
            return self._technique_result(raw.attack_id, raw)
        if isinstance(raw, Group):
            return self._group_result(raw.name, raw)
        if isinstance(raw, Software):
            return self._software_result(raw.name, raw)
        raise TypeError(f"cannot normalize {type(raw).__name__}; expected a MITRE ATT&CK view")

    # --- normalization: techniques (the rich blueprint) ------------------- #

    def _technique_result(self, entity_value: str, t: Technique) -> IntelligenceResult:
        references: list[Reference] = []
        if t.url:
            references.append(
                Reference(title=f"{t.attack_id}: {t.name}", url=t.url, description="MITRE ATT&CK")
            )
        references.extend(_reference(r) for r in (*t.capec, *t.references))

        relationships: list[Relationship] = []
        if t.parent:
            relationships.append(
                _relationship(
                    RelationshipType.PART_OF,
                    RelationshipTargetType.ATTACK_PATTERN,
                    t.parent.attack_id,
                    f"Sub-technique of {t.parent.name}",
                )
            )
        relationships.extend(
            _relationship(
                RelationshipType.RELATED_TO,
                RelationshipTargetType.ATTACK_PATTERN,
                s.attack_id,
                f"Sub-technique: {s.name}",
            )
            for s in t.subtechniques
        )
        relationships.extend(
            _relationship(
                RelationshipType.ASSOCIATED_WITH,
                RelationshipTargetType.THREAT_ACTOR,
                g.name,
                f"{g.attack_id} uses this technique",
            )
            for g in t.groups
        )
        relationships.extend(_software_relationship(s, "uses this technique") for s in t.software)
        relationships.extend(
            _relationship(
                RelationshipType.ASSOCIATED_WITH,
                RelationshipTargetType.CAMPAIGN,
                c.name,
                f"{c.attack_id} uses this technique",
            )
            for c in t.campaigns
        )
        relationships.extend(
            _relationship(
                RelationshipType.RELATED_TO,
                RelationshipTargetType.ATTACK_PATTERN,
                c.title,
                "CAPEC mapping",
            )
            for c in t.capec
        )

        evidence: list[Evidence] = [
            Evidence(
                type=EvidenceType.CLASSIFICATION,
                summary=f"MITRE ATT&CK technique {t.attack_id}: {t.name}",
                value=t.attack_id,
            )
        ]
        evidence.extend(
            Evidence(type=EvidenceType.CATEGORY, summary=f"Tactic: {tac}", value=tac)
            for tac in t.tactics
        )
        if t.detection:
            evidence.append(
                Evidence(
                    type=EvidenceType.DETECTION,
                    summary="Detection guidance available",
                    value=t.detection,
                )
            )
        evidence.extend(
            Evidence(
                type=EvidenceType.OTHER,
                summary=f"Mitigation: {m.attack_id} — {m.name}",
                value=m.attack_id,
            )
            for m in t.mitigations
        )

        metadata: dict[str, Any] = {
            "attack_id": t.attack_id,
            "name": t.name,
            "is_subtechnique": t.is_subtechnique,
        }
        _put(metadata, "description", t.description)
        _put(metadata, "tactics", list(t.tactics))
        _put(metadata, "platforms", list(t.platforms))
        _put(metadata, "permissions_required", list(t.permissions_required))
        _put(metadata, "data_sources", list(t.data_sources))
        _put(metadata, "detection", t.detection)
        if t.parent:
            metadata["parent_technique"] = t.parent.attack_id
        _put(metadata, "sub_techniques", [s.attack_id for s in t.subtechniques])
        _put(metadata, "mitigations", [{"id": m.attack_id, "name": m.name} for m in t.mitigations])
        _put(metadata, "dataset_version", self._dataset_version)

        return self._result(
            EntityType.MITRE_TECHNIQUE,
            entity_value,
            evidence=evidence,
            relationships=relationships,
            references=references,
            tags=_dedupe([*t.tactics, *t.platforms]),
            metadata=metadata,
        )

    # --- normalization: groups & software (leaner) ------------------------ #

    def _group_result(self, entity_value: str, g: Group) -> IntelligenceResult:
        references = _named_reference(g.attack_id, g.name, g.url) + [
            _reference(r) for r in g.references
        ]
        relationships = [
            _relationship(
                RelationshipType.USES,
                RelationshipTargetType.ATTACK_PATTERN,
                tech.attack_id,
                f"Uses {tech.name}",
            )
            for tech in g.techniques
        ]
        relationships.extend(_software_relationship(s, "is used by this group") for s in g.software)

        metadata: dict[str, Any] = {"attack_id": g.attack_id, "name": g.name}
        _put(metadata, "aliases", list(g.aliases))
        _put(metadata, "description", g.description)
        _put(metadata, "techniques", [t.attack_id for t in g.techniques])
        _put(metadata, "dataset_version", self._dataset_version)

        return self._result(
            EntityType.THREAT_ACTOR,
            entity_value,
            evidence=_knowledge_evidence("group", g.attack_id, g.name, g.aliases),
            relationships=relationships,
            references=references,
            tags=_dedupe(g.aliases),
            metadata=metadata,
        )

    def _software_result(self, entity_value: str, s: Software) -> IntelligenceResult:
        kind = "tool" if s.is_tool else "malware"
        references = _named_reference(s.attack_id, s.name, s.url) + [
            _reference(r) for r in s.references
        ]
        relationships = [
            _relationship(
                RelationshipType.USES,
                RelationshipTargetType.ATTACK_PATTERN,
                tech.attack_id,
                f"Uses {tech.name}",
            )
            for tech in s.techniques
        ]
        relationships.extend(
            _relationship(
                RelationshipType.ASSOCIATED_WITH,
                RelationshipTargetType.THREAT_ACTOR,
                grp.name,
                f"Used by {grp.attack_id}",
            )
            for grp in s.groups
        )

        metadata: dict[str, Any] = {
            "attack_id": s.attack_id,
            "name": s.name,
            "is_tool": s.is_tool,
        }
        _put(metadata, "aliases", list(s.aliases))
        _put(metadata, "description", s.description)
        _put(metadata, "techniques", [t.attack_id for t in s.techniques])
        _put(metadata, "dataset_version", self._dataset_version)

        return self._result(
            EntityType.MALWARE_FAMILY,
            entity_value,
            evidence=_knowledge_evidence(kind, s.attack_id, s.name, s.aliases),
            relationships=relationships,
            references=references,
            tags=_dedupe(s.aliases),
            metadata=metadata,
        )

    # --- shared construction ---------------------------------------------- #

    @property
    def _dataset_version(self) -> str | None:
        return self._dataset.provenance.version if self._dataset else None

    def _result(
        self,
        entity_type: EntityType,
        entity_value: str,
        *,
        evidence: list[Evidence],
        relationships: list[Relationship],
        references: list[Reference],
        tags: list[str],
        metadata: dict[str, Any],
    ) -> IntelligenceResult:
        return IntelligenceResult(
            provider=_NAME,
            provider_display_name=_DISPLAY,
            entity_type=entity_type,
            entity_value=entity_value,
            status=ResultStatus.OK,
            reputation=None,  # reference providers never assess reputation
            evidence=evidence,
            relationships=relationships,
            references=references,
            tags=tags,
            fetched_at=datetime.now(UTC),
            metadata=metadata,
        )


# --------------------------------------------------------------------------- #
# Module-level helpers
# --------------------------------------------------------------------------- #


def _resolve_dataset_path(explicit: Path | None) -> Path:
    if explicit is not None:
        return explicit
    env = os.getenv(_DATASET_ENV)
    return Path(env) if env else _BUNDLED_DATASET


def _relationship(
    verb: RelationshipType,
    target_type: RelationshipTargetType,
    target_value: str,
    description: str | None = None,
) -> Relationship:
    return Relationship(
        relationship=verb,
        target_type=target_type,
        target_value=target_value,
        description=description,
    )


def _software_relationship(s: SoftwareRef, action: str) -> Relationship:
    target_type = (
        RelationshipTargetType.TOOL if s.is_tool else RelationshipTargetType.MALWARE_FAMILY
    )
    return _relationship(
        RelationshipType.ASSOCIATED_WITH, target_type, s.name, f"{s.attack_id} {action}"
    )


def _reference(ref: ExternalRef) -> Reference:
    return Reference(title=ref.title, url=ref.url, description=ref.description)


def _named_reference(attack_id: str, name: str, url: str | None) -> list[Reference]:
    if not url:
        return []
    return [Reference(title=f"{attack_id}: {name}", url=url, description="MITRE ATT&CK")]


def _knowledge_evidence(
    kind: str, attack_id: str, name: str, aliases: Iterable[str]
) -> list[Evidence]:
    evidence = [
        Evidence(
            type=EvidenceType.CLASSIFICATION,
            summary=f"MITRE ATT&CK {kind} {attack_id}: {name}",
            value=attack_id,
        )
    ]
    evidence.extend(
        Evidence(type=EvidenceType.TAG, summary=f"Alias: {alias}", value=alias)
        for alias in aliases
        if alias.lower() != name.lower()
    )
    return evidence


def _put(metadata: dict[str, Any], key: str, value: Any) -> None:
    """Add ``value`` under ``key`` only when it carries content (skip empties)."""
    if value:
        metadata[key] = value


def _dedupe(values: Iterable[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        lowered = value.lower()
        if value and lowered not in seen:
            seen.add(lowered)
            out.append(value)
    return out
