"""Offline loader and index for NVD CVE data.

Loads a JSON file in NVD API 2.0 format (or the bundled curated subset) and
indexes CVEs by ID for O(1) lookup. CPE configurations are parsed into
vendor/product pairs; only the primary CVSS 3.x metric is retained.

No network is ever touched here. Online refresh is supported by pointing
NVD_DATASET_PATH at a file populated by an external tool.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

# --------------------------------------------------------------------------- #
# Typed views (no NVD API types leak past this module)
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class CvssMetric:
    """The primary CVSS metric for a CVE (V3.1 preferred over V3.0 over V2)."""

    version: str
    vector_string: str
    base_score: float
    base_severity: str
    attack_vector: str | None = None
    attack_complexity: str | None = None
    privileges_required: str | None = None
    user_interaction: str | None = None
    scope: str | None = None
    confidentiality: str | None = None
    integrity: str | None = None
    availability: str | None = None


@dataclass(frozen=True)
class AffectedProduct:
    """A vendor/product pair extracted from a CPE 2.3 string."""

    vendor: str
    product: str


@dataclass(frozen=True)
class NvdReference:
    """An external reference attached to a CVE."""

    url: str
    source: str | None = None
    tags: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class Cve:
    """A resolved CVE record ready for normalization."""

    id: str
    description: str
    published: str
    last_modified: str
    vuln_status: str | None
    cvss: CvssMetric | None
    cwes: tuple[str, ...]
    affected_products: tuple[AffectedProduct, ...]
    references: tuple[NvdReference, ...]


@dataclass(frozen=True)
class DatasetProvenance:
    """Version metadata describing the loaded dataset."""

    version: str | None = None
    release_date: str | None = None
    last_updated: datetime | None = None


# --------------------------------------------------------------------------- #
# Dataset
# --------------------------------------------------------------------------- #


class NvdDataset:
    """An indexed, read-only view over a NVD CVE JSON dataset.

    Built once at provider construction and queried per lookup. The bundled
    seed file covers a curated set of high-profile CVEs for offline use.
    Full datasets can be loaded via NVD_DATASET_PATH.
    """

    def __init__(self, data: dict[str, Any]) -> None:
        self._index: dict[str, Cve] = {}
        meta = data.get("_meta", {})
        self._provenance = DatasetProvenance(
            version=_text(meta.get("version")),
            release_date=_text(meta.get("release_date")),
            last_updated=_parse_time(meta.get("release_date")),
        )
        for vuln in data.get("vulnerabilities", []):
            if isinstance(vuln, dict):
                cve_obj = vuln.get("cve")
                if isinstance(cve_obj, dict):
                    cve = _parse_cve(cve_obj)
                    if cve is not None:
                        self._index[cve.id] = cve

    @classmethod
    def from_file(cls, path: Path) -> NvdDataset:
        """Load and index a NVD JSON dataset from ``path`` (offline)."""
        with path.open(encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, dict):
            raise ValueError("NVD dataset root must be a JSON object")
        return cls(data)

    @property
    def provenance(self) -> DatasetProvenance:
        """Version/date metadata for the loaded dataset."""
        return self._provenance

    def lookup(self, cve_id: str) -> Cve | None:
        """Return the CVE record for ``cve_id`` (case-insensitive), or None."""
        return self._index.get(cve_id.strip().upper())

    def __len__(self) -> int:
        return len(self._index)


# --------------------------------------------------------------------------- #
# Parsing helpers (private — NVD API 2.0 format)
# --------------------------------------------------------------------------- #


def _parse_cve(obj: dict[str, Any]) -> Cve | None:
    cve_id = _text(obj.get("id"))
    if not cve_id:
        return None

    description = _en_description(obj)
    published = _text(obj.get("published")) or ""
    last_modified = _text(obj.get("lastModified")) or ""
    vuln_status = _text(obj.get("vulnStatus"))

    cvss = _primary_cvss(obj.get("metrics", {}))
    cwes = tuple(_extract_cwes(obj.get("weaknesses", [])))
    products = tuple(_extract_products(obj.get("configurations", [])))
    references = tuple(_extract_references(obj.get("references", [])))

    return Cve(
        id=cve_id.upper(),
        description=description,
        published=published,
        last_modified=last_modified,
        vuln_status=vuln_status,
        cvss=cvss,
        cwes=cwes,
        affected_products=products,
        references=references,
    )


def _en_description(obj: dict[str, Any]) -> str:
    for desc in obj.get("descriptions", []):
        if isinstance(desc, dict) and desc.get("lang") == "en":
            text = _text(desc.get("value"))
            if text:
                return text
    return ""


def _primary_cvss(metrics: dict[str, Any]) -> CvssMetric | None:
    _CVSS_KEYS = (("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0"))
    for key, version in _CVSS_KEYS:
        entries = metrics.get(key, [])
        if not isinstance(entries, list) or not entries:
            continue
        # Prefer the "Primary" (NVD-sourced) metric; fall back to the first.
        entry = next((e for e in entries if e.get("type") == "Primary"), entries[0])
        data = entry.get("cvssData", {})
        score = data.get("baseScore")
        severity = _text(data.get("baseSeverity"))
        vector = _text(data.get("vectorString"))
        if score is None or not severity or not vector:
            continue
        try:
            score_f = float(score)
        except (TypeError, ValueError):
            continue
        return CvssMetric(
            version=version,
            vector_string=vector,
            base_score=score_f,
            base_severity=severity.upper(),
            attack_vector=_title(data.get("attackVector")),
            attack_complexity=_title(data.get("attackComplexity")),
            privileges_required=_title(data.get("privilegesRequired")),
            user_interaction=_title(data.get("userInteraction")),
            scope=_title(data.get("scope")),
            confidentiality=_title(data.get("confidentialityImpact")),
            integrity=_title(data.get("integrityImpact")),
            availability=_title(data.get("availabilityImpact")),
        )
    return None


def _extract_cwes(weaknesses: list[Any]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for weakness in weaknesses:
        if not isinstance(weakness, dict):
            continue
        for desc in weakness.get("description", []):
            if not isinstance(desc, dict) or desc.get("lang") != "en":
                continue
            value = _text(desc.get("value"))
            if value and value.startswith("CWE-") and value not in seen:
                seen.add(value)
                out.append(value)
    return out


def _extract_products(configurations: list[Any]) -> list[AffectedProduct]:
    seen: set[tuple[str, str]] = set()
    out: list[AffectedProduct] = []
    for config in configurations:
        if not isinstance(config, dict):
            continue
        for node in config.get("nodes", []):
            if not isinstance(node, dict):
                continue
            for cpe_match in node.get("cpeMatch", []):
                if not isinstance(cpe_match, dict) or not cpe_match.get("vulnerable", False):
                    continue
                product = _parse_cpe(cpe_match.get("criteria", ""))
                if product and product not in seen:
                    seen.add(product)
                    out.append(AffectedProduct(*product))
    return out


def _parse_cpe(criteria: str) -> tuple[str, str] | None:
    """Extract (vendor, product) from a CPE 2.3 string, or None."""
    parts = criteria.split(":")
    if len(parts) < 5 or parts[0] != "cpe" or parts[1] != "2.3":
        return None
    vendor = parts[3]
    product = parts[4]
    if not vendor or vendor == "*" or not product or product == "*":
        return None
    return (
        vendor.replace("_", " ").replace(".", " ").title(),
        product.replace("_", " ").replace(".", " ").title(),
    )


def _extract_references(refs: list[Any]) -> list[NvdReference]:
    out: list[NvdReference] = []
    seen: set[str] = set()
    for ref in refs:
        if not isinstance(ref, dict):
            continue
        url = _text(ref.get("url"))
        if not url or url in seen:
            continue
        seen.add(url)
        tags_raw = ref.get("tags", [])
        tags = tuple(t for t in tags_raw if isinstance(t, str) and t.strip())
        out.append(NvdReference(url=url, source=_text(ref.get("source")), tags=tags))
    return out


def _text(value: Any) -> str | None:
    if value is None:
        return None
    s = str(value).strip()
    return s or None


def _title(value: Any) -> str | None:
    t = _text(value)
    if t is None:
        return None
    return t.replace("_", " ").title()


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
