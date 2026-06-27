"""CAPEC (Common Attack Pattern Enumeration and Classification) provider.

Resolves CAPEC identifiers against an offline dataset and normalizes structured
attack-pattern data into the shared canonical
:class:`~threatlens.providers.results.IntelligenceResult` — evidence,
relationships, references, and metadata, but NEVER reputation (CAPEC is a
knowledge taxonomy, not a threat-intelligence feed).

CAPEC bridges software weaknesses (CWE) and attacker techniques (MITRE ATT&CK),
so its relationships complete the foundational knowledge graph:
``CAPEC → CWE`` (exploits a weakness), ``CAPEC → ATT&CK technique``, and
``CAPEC → related CAPEC``.

The provider supports:
- Offline use with the bundled curated seed dataset (default, no config needed).
- Full offline datasets by setting ``CAPEC_DATASET_PATH`` to a JSON file in the
  ThreatLens CAPEC format, populated externally.

The dataset is loaded lazily on first lookup and cached, so constructing the
provider (and routing non-CAPEC searches) never parses the file.
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
from .dataset import Capec, CapecDataset, CapecSkill, DatasetProvenance

_NAME = "capec"
_DISPLAY = "MITRE CAPEC"
_SOURCE_URL = "https://capec.mitre.org"
_PRIORITY = 55
_DATASET_ENV = "CAPEC_DATASET_PATH"
_BUNDLED_DATASET = Path(__file__).resolve().parent / "data" / "capec_seed.json"

_SUPPORTED = frozenset({EntityType.CAPEC})
_CAPABILITIES = frozenset({ReferenceCapability.ATTACK_PATTERN, ReferenceCapability.CROSS_REFERENCE})


class CapecProvider(ReferenceProvider):
    """Looks CAPEC identifiers up against an offline CAPEC dataset."""

    def __init__(
        self,
        *,
        dataset: CapecDataset | None = None,
        dataset_path: Path | None = None,
        enabled: bool = True,
    ) -> None:
        self._enabled = enabled
        self._load_error: str | None = None
        # An injected dataset is treated as already loaded; otherwise the parse
        # is deferred to the first lookup (lazy loading).
        self._dataset: CapecDataset | None = dataset
        self._loaded = dataset is not None
        self._dataset_path = None if dataset is not None else _resolve_dataset_path(dataset_path)

    @property
    def metadata(self) -> ReferenceMetadata:
        # Routing reads only the static identity (name, supported types,
        # capabilities, priority, enabled), so metadata never forces a parse.
        # Dataset provenance is folded in once a lookup has lazily loaded it;
        # the object is tiny, so it is rebuilt per call rather than cached.
        prov = self._dataset.provenance if self._dataset is not None else DatasetProvenance()
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

    def _ensure_dataset(self) -> CapecDataset | None:
        """Load and cache the dataset on first call (idempotent, never raises)."""
        if not self._loaded:
            self._loaded = True
            assert self._dataset_path is not None
            try:
                self._dataset = CapecDataset.from_file(self._dataset_path)
            except (OSError, ValueError) as exc:
                self._dataset = None
                self._load_error = f"could not load CAPEC dataset from {self._dataset_path}: {exc}"
        return self._dataset

    async def lookup(self, entity: Entity) -> IntelligenceResult:
        """Resolve ``entity`` against the CAPEC dataset (never raises)."""
        if not self.supports(entity.type):
            return self._unsupported(entity.type, entity.value)
        dataset = self._ensure_dataset()
        if dataset is None:
            return self._fail(
                entity,
                ResultStatus.ERROR,
                "CAPEC dataset unavailable",
                detail=self._load_error,
            )

        key = entity.normalized_value or entity.value
        capec = dataset.lookup(key)
        if capec is None:
            return self._not_found(entity.type, entity.value)
        return self._capec_result(entity.value, capec)

    async def normalize(self, raw: Any) -> IntelligenceResult:
        """Map a :class:`~.dataset.Capec` view into a canonical result."""
        if isinstance(raw, Capec):
            return self._capec_result(raw.capec_id, raw)
        raise TypeError(f"cannot normalize {type(raw).__name__}; expected a Capec view")

    # --- normalization ------------------------------------------------------- #

    def _capec_result(self, entity_value: str, capec: Capec) -> IntelligenceResult:
        evidence = _build_evidence(capec)
        relationships = _build_relationships(capec)
        references = _build_references(capec)
        tags = [capec.capec_id]
        if capec.typical_severity:
            tags.append(capec.typical_severity)

        metadata: dict[str, Any] = {
            "capec_id": capec.capec_id,
            "name": capec.name,
            "description": capec.description,
        }
        _put(metadata, "extended_description", capec.extended_description)
        _put(metadata, "abstraction", capec.abstraction)
        _put(metadata, "typical_severity", capec.typical_severity)
        _put(metadata, "likelihood_of_attack", capec.likelihood_of_attack)
        _put(metadata, "prerequisites", list(capec.prerequisites))
        if capec.skills_required:
            metadata["skills_required"] = [_skill_dict(s) for s in capec.skills_required]
        _put(metadata, "resources_required", list(capec.resources_required))
        _put(metadata, "indicators", list(capec.indicators))
        if capec.execution_flow:
            metadata["execution_flow"] = [
                {"step": s.step, "phase": s.phase, "description": s.description}
                for s in capec.execution_flow
            ]
        _put(metadata, "mitigations", list(capec.mitigations))
        if capec.related_weaknesses:
            metadata["related_weaknesses"] = [f"CWE-{n}" for n in capec.related_weaknesses]
        if capec.related_attack_patterns:
            metadata["related_attack_patterns"] = [
                f"CAPEC-{r.capec_id}" for r in capec.related_attack_patterns
            ]
        _put(metadata, "related_techniques", list(capec.related_techniques))

        return IntelligenceResult(
            provider=_NAME,
            provider_display_name=_DISPLAY,
            entity_type=EntityType.CAPEC,
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


def _build_evidence(capec: Capec) -> list[Evidence]:
    evidence: list[Evidence] = [
        Evidence(
            type=EvidenceType.CLASSIFICATION,
            summary=f"{capec.capec_id}: {capec.name}",
            value=capec.capec_id,
        )
    ]

    if capec.typical_severity:
        evidence.append(
            Evidence(
                type=EvidenceType.CATEGORY,
                summary=f"Typical Severity: {capec.typical_severity}",
                value=capec.typical_severity,
            )
        )
    if capec.likelihood_of_attack:
        evidence.append(
            Evidence(
                type=EvidenceType.CATEGORY,
                summary=f"Likelihood of Attack: {capec.likelihood_of_attack}",
                value=capec.likelihood_of_attack,
            )
        )
    if capec.abstraction:
        evidence.append(
            Evidence(
                type=EvidenceType.CATEGORY,
                summary=f"Abstraction: {capec.abstraction}",
                value=capec.abstraction,
            )
        )

    # Indicators render as the card's Detection Guidance section.
    if capec.indicators:
        evidence.append(
            Evidence(
                type=EvidenceType.DETECTION,
                summary="Detection indicators available",
                value="; ".join(capec.indicators),
            )
        )

    # Prefixed "Mitigation:" so the Knowledge card groups these under Mitigations.
    for m in capec.mitigations:
        evidence.append(Evidence(type=EvidenceType.OTHER, summary=f"Mitigation: {m}"))

    for p in capec.prerequisites:
        evidence.append(Evidence(type=EvidenceType.OTHER, summary=f"Prerequisite: {p}"))

    for s in capec.skills_required:
        summary = f"Skill Required ({s.level})"
        if s.description:
            summary = f"{summary}: {s.description}"
        evidence.append(Evidence(type=EvidenceType.OTHER, summary=summary))

    for r in capec.resources_required:
        evidence.append(Evidence(type=EvidenceType.OTHER, summary=f"Resource Required: {r}"))

    for step in capec.execution_flow:
        label = f"Execution Step {step.step}" if step.step is not None else "Execution Step"
        evidence.append(
            Evidence(type=EvidenceType.OTHER, summary=f"{label} ({step.phase}): {step.description}")
        )

    return evidence


def _build_relationships(capec: Capec) -> list[Relationship]:
    rels: list[Relationship] = []

    # CAPEC → CWE: the attack pattern exploits the weakness.
    for cwe_id in capec.related_weaknesses:
        rels.append(
            Relationship(
                relationship=RelationshipType.EXPLOITS,
                target_type=RelationshipTargetType.WEAKNESS,
                target_value=f"CWE-{cwe_id}",
                description=f"{capec.capec_id} exploits this weakness",
            )
        )

    # CAPEC → MITRE ATT&CK technique (both are STIX attack-patterns).
    for tech in capec.related_techniques:
        rels.append(
            Relationship(
                relationship=RelationshipType.RELATED_TO,
                target_type=RelationshipTargetType.ATTACK_PATTERN,
                target_value=tech,
                description="ATT&CK technique mapping",
            )
        )

    # CAPEC → related CAPEC.
    for r in capec.related_attack_patterns:
        rels.append(
            Relationship(
                relationship=RelationshipType.RELATED_TO,
                target_type=RelationshipTargetType.ATTACK_PATTERN,
                target_value=f"CAPEC-{r.capec_id}",
                description=r.nature,
            )
        )

    return rels


def _build_references(capec: Capec) -> list[Reference]:
    canonical = f"https://capec.mitre.org/data/definitions/{capec.id}.html"
    refs: list[Reference] = [
        Reference(
            title=f"{capec.capec_id} — MITRE CAPEC",
            url=canonical,
            description="MITRE Common Attack Pattern Enumeration and Classification",
        )
    ]
    for r in capec.references:
        if r.url and r.url != canonical:
            refs.append(Reference(title=r.title, url=r.url))
    return refs


def _skill_dict(s: CapecSkill) -> dict[str, Any]:
    d: dict[str, Any] = {"level": s.level}
    if s.description:
        d["description"] = s.description
    return d


def _resolve_dataset_path(explicit: Path | None) -> Path:
    if explicit is not None:
        return explicit
    env = os.getenv(_DATASET_ENV)
    return Path(env) if env else _BUNDLED_DATASET


def _put(d: dict[str, Any], key: str, value: Any) -> None:
    if value:
        d[key] = value
