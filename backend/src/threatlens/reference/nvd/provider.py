"""NVD (National Vulnerability Database) reference provider.

Resolves CVE identifiers against an offline NVD dataset and normalizes the
structured vulnerability data into the shared canonical
:class:`~threatlens.providers.results.IntelligenceResult` — evidence,
relationships, references, and metadata, but NEVER reputation (NVD is a
knowledge source, not a threat-intelligence feed).

The provider supports:
- Offline use with the bundled curated seed dataset (default, no config needed).
- Full offline datasets by setting ``NVD_DATASET_PATH`` to a JSON file in NVD
  API 2.0 format, populated externally (e.g., via the official NVD API).
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
from .dataset import Cve, CvssMetric, DatasetProvenance, NvdDataset

_NAME = "nvd"
_DISPLAY = "National Vulnerability Database"
_SOURCE_URL = "https://nvd.nist.gov"
_PRIORITY = 50
_DATASET_ENV = "NVD_DATASET_PATH"
_BUNDLED_DATASET = Path(__file__).resolve().parent / "data" / "nvd_seed.json"

_SUPPORTED = frozenset({EntityType.CVE})
_CAPABILITIES = frozenset({ReferenceCapability.VULNERABILITY, ReferenceCapability.CROSS_REFERENCE})


class NvdProvider(ReferenceProvider):
    """Looks CVEs up against an offline NVD dataset."""

    def __init__(
        self,
        *,
        dataset: NvdDataset | None = None,
        dataset_path: Path | None = None,
        enabled: bool = True,
    ) -> None:
        self._enabled = enabled
        self._load_error: str | None = None
        self._cached_metadata: ReferenceMetadata | None = None
        if dataset is not None:
            self._dataset: NvdDataset | None = dataset
            return
        path = _resolve_dataset_path(dataset_path)
        try:
            self._dataset = NvdDataset.from_file(path)
        except (OSError, ValueError) as exc:
            self._dataset = None
            self._load_error = f"could not load NVD dataset from {path}: {exc}"

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
        """Resolve ``entity`` against the NVD dataset (never raises)."""
        if not self.supports(entity.type):
            return self._unsupported(entity.type, entity.value)
        if self._dataset is None:
            return self._fail(
                entity,
                ResultStatus.ERROR,
                "NVD dataset unavailable",
                detail=self._load_error,
            )

        key = entity.normalized_value or entity.value
        cve = self._dataset.lookup(key)
        if cve is None:
            return self._not_found(entity.type, entity.value)
        return self._cve_result(entity.value, cve)

    async def normalize(self, raw: Any) -> IntelligenceResult:
        """Map a :class:`~.dataset.Cve` view into a canonical result."""
        if isinstance(raw, Cve):
            return self._cve_result(raw.id, raw)
        raise TypeError(f"cannot normalize {type(raw).__name__}; expected a Cve view")

    # --- normalization ------------------------------------------------------- #

    def _cve_result(self, entity_value: str, cve: Cve) -> IntelligenceResult:
        evidence = _build_evidence(cve)
        relationships = _build_relationships(cve)
        references = _build_references(cve)
        tags = [cve.id]
        if cve.cvss:
            tags.append(cve.cvss.base_severity)

        metadata: dict[str, Any] = {
            "cve_id": cve.id,
            "description": cve.description,
        }
        _put(metadata, "published", _date_part(cve.published))
        _put(metadata, "last_modified", _date_part(cve.last_modified))
        _put(metadata, "vuln_status", cve.vuln_status)
        if cve.cvss:
            metadata["cvss"] = _cvss_metadata(cve.cvss)
        _put(metadata, "cwes", list(cve.cwes))
        if cve.affected_products:
            metadata["affected_products"] = [
                {"vendor": p.vendor, "product": p.product} for p in cve.affected_products
            ]

        return IntelligenceResult(
            provider=_NAME,
            provider_display_name=_DISPLAY,
            entity_type=EntityType.CVE,
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


def _build_evidence(cve: Cve) -> list[Evidence]:
    evidence: list[Evidence] = []

    # Primary classification: severity + score (shown in collapsed card preview)
    if cve.cvss:
        c = cve.cvss
        evidence.append(
            Evidence(
                type=EvidenceType.CLASSIFICATION,
                summary=f"CVSS {c.version} Base Score: {c.base_score} ({c.base_severity})",
                value=str(c.base_score),
            )
        )
        evidence.append(
            Evidence(
                type=EvidenceType.CATEGORY,
                summary=f"Severity: {c.base_severity}",
                value=c.base_severity,
            )
        )
        if c.attack_vector:
            evidence.append(
                Evidence(type=EvidenceType.OTHER, summary=f"Attack Vector: {c.attack_vector}")
            )
        if c.attack_complexity:
            evidence.append(
                Evidence(
                    type=EvidenceType.OTHER,
                    summary=f"Attack Complexity: {c.attack_complexity}",
                )
            )
        if c.privileges_required:
            evidence.append(
                Evidence(
                    type=EvidenceType.OTHER,
                    summary=f"Privileges Required: {c.privileges_required}",
                )
            )
        if c.user_interaction:
            evidence.append(
                Evidence(
                    type=EvidenceType.OTHER,
                    summary=f"User Interaction: {c.user_interaction}",
                )
            )
        if c.scope:
            evidence.append(Evidence(type=EvidenceType.OTHER, summary=f"Scope: {c.scope}"))
        if c.confidentiality:
            evidence.append(
                Evidence(
                    type=EvidenceType.OTHER,
                    summary=f"Confidentiality Impact: {c.confidentiality}",
                )
            )
        if c.integrity:
            evidence.append(
                Evidence(type=EvidenceType.OTHER, summary=f"Integrity Impact: {c.integrity}")
            )
        if c.availability:
            evidence.append(
                Evidence(type=EvidenceType.OTHER, summary=f"Availability Impact: {c.availability}")
            )
        evidence.append(
            Evidence(type=EvidenceType.OTHER, summary=f"Vector String: {c.vector_string}")
        )
    elif cve.description:
        # No CVSS; fall back to description as classification
        evidence.append(Evidence(type=EvidenceType.CLASSIFICATION, summary=cve.description[:200]))

    # Publication dates
    published = _date_part(cve.published)
    if published:
        evidence.append(Evidence(type=EvidenceType.FIRST_SEEN, summary=f"Published: {published}"))
    modified = _date_part(cve.last_modified)
    if modified:
        evidence.append(Evidence(type=EvidenceType.LAST_SEEN, summary=f"Last Modified: {modified}"))

    # CWEs as category tags (also appear as relationships)
    for cwe in cve.cwes:
        evidence.append(Evidence(type=EvidenceType.CATEGORY, summary=cwe, value=cwe))

    return evidence


def _build_relationships(cve: Cve) -> list[Relationship]:
    return [
        Relationship(
            relationship=RelationshipType.RELATED_TO,
            target_type=RelationshipTargetType.WEAKNESS,
            target_value=cwe,
            description=f"Weakness type associated with {cve.id}",
        )
        for cwe in cve.cwes
    ]


def _build_references(cve: Cve) -> list[Reference]:
    refs: list[Reference] = []
    # NVD canonical page first
    refs.append(
        Reference(
            title=f"{cve.id} — NVD",
            url=f"https://nvd.nist.gov/vuln/detail/{cve.id}",
            description="National Vulnerability Database",
        )
    )
    for r in cve.references:
        tag_str = ", ".join(r.tags) if r.tags else None
        refs.append(Reference(title=r.url, url=r.url, description=tag_str))
    return refs


def _cvss_metadata(c: CvssMetric) -> dict[str, Any]:
    meta: dict[str, Any] = {
        "version": c.version,
        "base_score": c.base_score,
        "base_severity": c.base_severity,
        "vector_string": c.vector_string,
    }
    _put(meta, "attack_vector", c.attack_vector)
    _put(meta, "attack_complexity", c.attack_complexity)
    _put(meta, "privileges_required", c.privileges_required)
    _put(meta, "user_interaction", c.user_interaction)
    _put(meta, "scope", c.scope)
    _put(meta, "confidentiality", c.confidentiality)
    _put(meta, "integrity", c.integrity)
    _put(meta, "availability", c.availability)
    return meta


def _resolve_dataset_path(explicit: Path | None) -> Path:
    if explicit is not None:
        return explicit
    env = os.getenv(_DATASET_ENV)
    return Path(env) if env else _BUNDLED_DATASET


def _put(d: dict[str, Any], key: str, value: Any) -> None:
    if value:
        d[key] = value


def _date_part(value: str) -> str | None:
    if not value:
        return None
    return value[:10] if len(value) >= 10 else value
