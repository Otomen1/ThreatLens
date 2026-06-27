"""CWE (Common Weakness Enumeration) reference provider.

Resolves CWE identifiers against an offline dataset and normalizes structured
weakness data into the shared canonical
:class:`~threatlens.providers.results.IntelligenceResult` — evidence,
relationships, references, and metadata, but NEVER reputation (CWE is a
knowledge taxonomy, not a threat-intelligence feed).

The provider supports:
- Offline use with the bundled curated seed dataset (default, no config needed).
- Full offline datasets by setting ``CWE_DATASET_PATH`` to a JSON file in the
  ThreatLens CWE format, populated externally.
"""

from __future__ import annotations

import os
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
from .dataset import Cwe, CweConsequence, CweDataset, DatasetProvenance

_NAME = "cwe"
_DISPLAY = "MITRE CWE"
_SOURCE_URL = "https://cwe.mitre.org"
_PRIORITY = 55
_DATASET_ENV = "CWE_DATASET_PATH"
_BUNDLED_DATASET = Path(__file__).resolve().parent / "data" / "cwe_seed.json"

_SUPPORTED = frozenset({EntityType.CWE})
_CAPABILITIES = frozenset({ReferenceCapability.WEAKNESS, ReferenceCapability.CROSS_REFERENCE})


class CweProvider(ReferenceProvider):
    """Looks CWE identifiers up against an offline CWE dataset."""

    def __init__(
        self,
        *,
        dataset: CweDataset | None = None,
        dataset_path: Path | None = None,
        enabled: bool = True,
    ) -> None:
        self._enabled = enabled
        self._load_error: str | None = None
        self._cached_metadata: ReferenceMetadata | None = None
        if dataset is not None:
            self._dataset: CweDataset | None = dataset
            return
        path = _resolve_dataset_path(dataset_path)
        try:
            self._dataset = CweDataset.from_file(path)
        except (OSError, ValueError) as exc:
            self._dataset = None
            self._load_error = f"could not load CWE dataset from {path}: {exc}"

    @property
    def metadata(self) -> ReferenceMetadata:
        if self._cached_metadata is None:
            prov = self._dataset.provenance if self._dataset else DatasetProvenance()
            self._cached_metadata = ReferenceMetadata(
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
        return self._cached_metadata

    async def lookup(self, entity: Entity) -> IntelligenceResult:
        """Resolve ``entity`` against the CWE dataset (never raises)."""
        if not self.supports(entity.type):
            return self._unsupported(entity.type, entity.value)
        if self._dataset is None:
            return self._fail(
                entity,
                ResultStatus.ERROR,
                "CWE dataset unavailable",
                detail=self._load_error,
            )

        key = entity.normalized_value or entity.value
        cwe = self._dataset.lookup(key)
        if cwe is None:
            return self._not_found(entity.type, entity.value)
        return self._cwe_result(entity.value, cwe)

    async def normalize(self, raw: Any) -> IntelligenceResult:
        """Map a :class:`~.dataset.Cwe` view into a canonical result."""
        if isinstance(raw, Cwe):
            return self._cwe_result(raw.cwe_id, raw)
        raise TypeError(f"cannot normalize {type(raw).__name__}; expected a Cwe view")

    # --- normalization ------------------------------------------------------- #

    def _cwe_result(self, entity_value: str, cwe: Cwe) -> IntelligenceResult:
        evidence = _build_evidence(cwe)
        relationships = _build_relationships(cwe)
        references = _build_references(cwe)
        tags = [cwe.cwe_id]
        if cwe.likelihood_of_exploit:
            tags.append(cwe.likelihood_of_exploit)

        metadata: dict[str, Any] = {
            "cwe_id": cwe.cwe_id,
            "name": cwe.name,
            "description": cwe.description,
        }
        _put(metadata, "extended_description", cwe.extended_description)
        _put(metadata, "likelihood_of_exploit", cwe.likelihood_of_exploit)
        if cwe.applicable_platforms:
            metadata["applicable_platforms"] = list(cwe.applicable_platforms)
        if cwe.common_consequences:
            metadata["common_consequences"] = [
                _consequence_dict(c) for c in cwe.common_consequences
            ]
        if cwe.detection_methods:
            metadata["detection_methods"] = [
                {"method": d.method, "description": d.description} for d in cwe.detection_methods
            ]
        if cwe.mitigations:
            metadata["mitigations"] = [
                {"phase": m.phase, "description": m.description} for m in cwe.mitigations
            ]
        if cwe.related_attack_patterns:
            metadata["related_attack_patterns"] = [
                f"CAPEC-{n}" for n in cwe.related_attack_patterns
            ]

        return IntelligenceResult(
            provider=_NAME,
            provider_display_name=_DISPLAY,
            entity_type=EntityType.CWE,
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
# Module-level builders
# --------------------------------------------------------------------------- #


def _build_evidence(cwe: Cwe) -> list[Evidence]:
    evidence: list[Evidence] = []

    # Primary classification
    evidence.append(
        Evidence(
            type=EvidenceType.CLASSIFICATION,
            summary=f"{cwe.cwe_id}: {cwe.name}",
            value=cwe.cwe_id,
        )
    )

    if cwe.likelihood_of_exploit:
        evidence.append(
            Evidence(
                type=EvidenceType.CATEGORY,
                summary=f"Likelihood of Exploit: {cwe.likelihood_of_exploit}",
                value=cwe.likelihood_of_exploit,
            )
        )

    for platform in cwe.applicable_platforms:
        evidence.append(
            Evidence(type=EvidenceType.OTHER, summary=f"Applicable Platform: {platform}")
        )

    for c in cwe.common_consequences:
        summary = f"Consequence: {c.scope} — {c.impact}"
        evidence.append(Evidence(type=EvidenceType.OTHER, summary=summary))

    for d in cwe.detection_methods:
        evidence.append(Evidence(type=EvidenceType.OTHER, summary=f"Detection Method: {d.method}"))

    return evidence


def _build_relationships(cwe: Cwe) -> list[Relationship]:
    rels: list[Relationship] = []

    # Parent CWE relationships (ChildOf → the parent is a weakness)
    for rw in cwe.related_weaknesses:
        rels.append(
            Relationship(
                relationship=RelationshipType.RELATED_TO,
                target_type=RelationshipTargetType.WEAKNESS,
                target_value=f"CWE-{rw.cwe_id}",
                description=rw.nature,
            )
        )

    # CAPEC attack-pattern relationships
    for capec_id in cwe.related_attack_patterns:
        rels.append(
            Relationship(
                relationship=RelationshipType.RELATED_TO,
                target_type=RelationshipTargetType.ATTACK_PATTERN,
                target_value=f"CAPEC-{capec_id}",
                description=f"Attack pattern exploiting {cwe.cwe_id}",
            )
        )

    return rels


def _build_references(cwe: Cwe) -> list[Reference]:
    refs: list[Reference] = []
    # CWE canonical page first
    refs.append(
        Reference(
            title=f"{cwe.cwe_id} — MITRE CWE",
            url=f"https://cwe.mitre.org/data/definitions/{cwe.id}.html",
            description="MITRE Common Weakness Enumeration",
        )
    )
    for r in cwe.references:
        if r.url and r.url != f"https://cwe.mitre.org/data/definitions/{cwe.id}.html":
            refs.append(Reference(title=r.title, url=r.url))
    return refs


def _consequence_dict(c: CweConsequence) -> dict[str, Any]:
    d: dict[str, Any] = {"scope": c.scope, "impact": c.impact}
    if c.note:
        d["note"] = c.note
    return d


def _resolve_dataset_path(explicit: Path | None) -> Path:
    if explicit is not None:
        return explicit
    env = os.getenv(_DATASET_ENV)
    return Path(env) if env else _BUNDLED_DATASET


def _put(d: dict[str, Any], key: str, value: Any) -> None:
    if value:
        d[key] = value
