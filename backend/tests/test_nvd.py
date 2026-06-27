"""Tests for the NVD reference provider (Phase 2.1).

Fully offline and deterministic: the provider loads the bundled curated seed
dataset or tiny in-memory dicts — no network is ever touched. Covers CVE
lookups, CVSS normalisation, CWE relationships, affected product extraction,
reference building, metadata structure, provenance, missing-dataset path,
unsupported entity types, and aggregation compatibility.
"""

from __future__ import annotations

import pytest

from threatlens.entities.models import Entity
from threatlens.entities.types import EntityType, ValidationStatus
from threatlens.providers import (
    IntelligenceResult,
    RelationshipTargetType,
    RelationshipType,
    ResultStatus,
    aggregate,
)
from threatlens.reference import NvdDataset, NvdProvider, build_default_reference_registry
from threatlens.reference.nvd import Cve, CvssMetric
from threatlens.reference.nvd.dataset import AffectedProduct, NvdReference

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def make_entity(entity_type: EntityType, value: str, normalized: str | None = None) -> Entity:
    return Entity(
        type=entity_type,
        value=value,
        normalized_value=normalized or value,
        confidence=100,
        validation=ValidationStatus.VALID,
    )


def cve_entity(value: str, normalized: str | None = None) -> Entity:
    return make_entity(EntityType.CVE, value, normalized)


def provider() -> NvdProvider:
    """Provider backed by the bundled offline dataset."""
    return NvdProvider()


def evidence_summaries(result: IntelligenceResult) -> list[str]:
    return [e.summary for e in result.evidence]


def evidence_types(result: IntelligenceResult) -> list[str]:
    return [e.type for e in result.evidence]


def relationship_targets(
    result: IntelligenceResult, target_type: RelationshipTargetType
) -> list[str]:
    return [r.target_value for r in result.relationships if r.target_type is target_type]


# --------------------------------------------------------------------------- #
# Minimal in-memory dataset for dataset-unit and normalize() tests
# --------------------------------------------------------------------------- #

MINI_DATA: dict[str, object] = {
    "_meta": {
        "version": "2024.01.01",
        "release_date": "2024-01-01",
    },
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2099-99999",
                "published": "2099-01-01T00:00:00.000",
                "lastModified": "2099-06-01T00:00:00.000",
                "vulnStatus": "Analyzed",
                "descriptions": [{"lang": "en", "value": "A test vulnerability for unit testing."}],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                "attackVector": "NETWORK",
                                "attackComplexity": "LOW",
                                "privilegesRequired": "NONE",
                                "userInteraction": "NONE",
                                "scope": "UNCHANGED",
                                "confidentialityImpact": "HIGH",
                                "integrityImpact": "HIGH",
                                "availabilityImpact": "HIGH",
                                "baseScore": 9.8,
                                "baseSeverity": "CRITICAL",
                            },
                        }
                    ]
                },
                "weaknesses": [
                    {
                        "type": "Primary",
                        "description": [{"lang": "en", "value": "CWE-89"}],
                    }
                ],
                "configurations": [
                    {
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:a:example:widget:1.0:*:*:*:*:*:*:*",
                                    }
                                ],
                            }
                        ]
                    }
                ],
                "references": [
                    {
                        "url": "https://example.com/advisory",
                        "source": "example.com",
                        "tags": ["Vendor Advisory"],
                    }
                ],
            }
        }
    ],
}


# --------------------------------------------------------------------------- #
# Dataset unit tests
# --------------------------------------------------------------------------- #


class TestNvdDataset:
    def test_loads_mini_dataset(self) -> None:
        ds = NvdDataset(MINI_DATA)  # type: ignore[arg-type]
        assert len(ds) == 1

    def test_lookup_by_id(self) -> None:
        ds = NvdDataset(MINI_DATA)  # type: ignore[arg-type]
        cve = ds.lookup("CVE-2099-99999")
        assert cve is not None
        assert cve.id == "CVE-2099-99999"

    def test_lookup_case_insensitive(self) -> None:
        ds = NvdDataset(MINI_DATA)  # type: ignore[arg-type]
        assert ds.lookup("cve-2099-99999") is not None

    def test_lookup_missing_returns_none(self) -> None:
        ds = NvdDataset(MINI_DATA)  # type: ignore[arg-type]
        assert ds.lookup("CVE-0000-00000") is None

    def test_provenance_parsed(self) -> None:
        ds = NvdDataset(MINI_DATA)  # type: ignore[arg-type]
        assert ds.provenance.version == "2024.01.01"
        assert ds.provenance.release_date == "2024-01-01"

    def test_cvss_parsed(self) -> None:
        ds = NvdDataset(MINI_DATA)  # type: ignore[arg-type]
        cve = ds.lookup("CVE-2099-99999")
        assert cve is not None
        assert cve.cvss is not None
        assert cve.cvss.base_score == 9.8
        assert cve.cvss.base_severity == "CRITICAL"
        assert cve.cvss.version == "3.1"
        assert cve.cvss.attack_vector == "Network"
        assert cve.cvss.attack_complexity == "Low"

    def test_cwes_parsed(self) -> None:
        ds = NvdDataset(MINI_DATA)  # type: ignore[arg-type]
        cve = ds.lookup("CVE-2099-99999")
        assert cve is not None
        assert "CWE-89" in cve.cwes

    def test_affected_products_parsed(self) -> None:
        ds = NvdDataset(MINI_DATA)  # type: ignore[arg-type]
        cve = ds.lookup("CVE-2099-99999")
        assert cve is not None
        assert len(cve.affected_products) == 1
        p = cve.affected_products[0]
        assert p.vendor == "Example"
        assert p.product == "Widget"

    def test_references_parsed(self) -> None:
        ds = NvdDataset(MINI_DATA)  # type: ignore[arg-type]
        cve = ds.lookup("CVE-2099-99999")
        assert cve is not None
        assert len(cve.references) == 1
        ref = cve.references[0]
        assert ref.url == "https://example.com/advisory"
        assert "Vendor Advisory" in ref.tags

    def test_empty_vulnerabilities(self) -> None:
        ds = NvdDataset({"vulnerabilities": []})
        assert len(ds) == 0


# --------------------------------------------------------------------------- #
# Bundled dataset tests
# --------------------------------------------------------------------------- #


class TestBundledDataset:
    def test_loads_without_error(self) -> None:
        p = provider()
        assert p.metadata.dataset_version is not None

    def test_log4shell_present(self) -> None:
        p = provider()
        ds = p._dataset
        assert ds is not None
        cve = ds.lookup("CVE-2021-44228")
        assert cve is not None
        assert cve.cvss is not None
        assert cve.cvss.base_score == 10.0
        assert cve.cvss.base_severity == "CRITICAL"

    def test_heartbleed_present(self) -> None:
        p = provider()
        ds = p._dataset
        assert ds is not None
        cve = ds.lookup("CVE-2014-0160")
        assert cve is not None
        assert cve.cvss is not None
        assert cve.cvss.base_severity == "HIGH"

    def test_provenance_fields(self) -> None:
        p = provider()
        meta = p.metadata
        assert meta.dataset_version == "2024.12.01"
        assert meta.release_date == "2024-12-01"
        assert meta.offline is True
        assert meta.source_url == "https://nvd.nist.gov"


# --------------------------------------------------------------------------- #
# Metadata / registration
# --------------------------------------------------------------------------- #


class TestProviderMetadata:
    def test_name_and_display(self) -> None:
        p = provider()
        assert p.name == "nvd"
        assert p.metadata.display_name == "National Vulnerability Database"

    def test_supports_cve_only(self) -> None:
        p = provider()
        assert p.supports(EntityType.CVE)
        for other in (
            EntityType.MITRE_TECHNIQUE,
            EntityType.THREAT_ACTOR,
            EntityType.MALWARE_FAMILY,
            EntityType.IPV4,
            EntityType.DOMAIN,
            EntityType.SHA256,
        ):
            assert not p.supports(other)

    def test_default_registry_includes_nvd(self) -> None:
        registry = build_default_reference_registry()
        assert "nvd" in registry

    def test_enabled_by_default(self) -> None:
        assert provider().enabled is True

    def test_disabled_flag(self) -> None:
        p = NvdProvider(enabled=False)
        assert p.enabled is False


# --------------------------------------------------------------------------- #
# lookup() — happy paths
# --------------------------------------------------------------------------- #


class TestLookup:
    @pytest.mark.asyncio
    async def test_lookup_log4shell(self) -> None:
        result = await provider().lookup(cve_entity("CVE-2021-44228"))
        assert result.status == ResultStatus.OK
        assert result.reputation is None

    @pytest.mark.asyncio
    async def test_lookup_case_insensitive(self) -> None:
        result = await provider().lookup(cve_entity("cve-2021-44228", "CVE-2021-44228"))
        assert result.status == ResultStatus.OK

    @pytest.mark.asyncio
    async def test_not_found(self) -> None:
        result = await provider().lookup(cve_entity("CVE-9999-99999"))
        assert result.status == ResultStatus.NOT_FOUND

    @pytest.mark.asyncio
    async def test_unsupported_entity_type(self) -> None:
        entity = make_entity(EntityType.IPV4, "1.2.3.4")
        result = await provider().lookup(entity)
        assert result.status == ResultStatus.UNSUPPORTED

    @pytest.mark.asyncio
    async def test_safe_lookup_returns_error_on_missing_dataset(self) -> None:
        from pathlib import Path

        p = NvdProvider(dataset_path=Path("/nonexistent/path.json"))
        result = await p.safe_lookup(cve_entity("CVE-2021-44228"))
        assert result.status == ResultStatus.ERROR


# --------------------------------------------------------------------------- #
# Evidence content
# --------------------------------------------------------------------------- #


class TestEvidence:
    @pytest.mark.asyncio
    async def test_classification_evidence_present(self) -> None:
        result = await provider().lookup(cve_entity("CVE-2021-44228"))
        types = evidence_types(result)
        assert "classification" in types

    @pytest.mark.asyncio
    async def test_classification_contains_score_and_severity(self) -> None:
        result = await provider().lookup(cve_entity("CVE-2021-44228"))
        classification = next(e for e in result.evidence if e.type == "classification")
        assert "10.0" in classification.summary
        assert "CRITICAL" in classification.summary

    @pytest.mark.asyncio
    async def test_severity_category_evidence(self) -> None:
        result = await provider().lookup(cve_entity("CVE-2021-44228"))
        cats = [e for e in result.evidence if e.type == "category"]
        severities = [c.value for c in cats if c.value in ("CRITICAL", "HIGH", "MEDIUM", "LOW")]
        assert "CRITICAL" in severities

    @pytest.mark.asyncio
    async def test_attack_vector_evidence(self) -> None:
        result = await provider().lookup(cve_entity("CVE-2021-44228"))
        summaries = evidence_summaries(result)
        assert any("Attack Vector" in s for s in summaries)

    @pytest.mark.asyncio
    async def test_vector_string_evidence(self) -> None:
        result = await provider().lookup(cve_entity("CVE-2021-44228"))
        summaries = evidence_summaries(result)
        assert any("CVSS:3.1/AV:" in s for s in summaries)

    @pytest.mark.asyncio
    async def test_published_evidence(self) -> None:
        result = await provider().lookup(cve_entity("CVE-2021-44228"))
        summaries = evidence_summaries(result)
        assert any("Published" in s and "2021" in s for s in summaries)

    @pytest.mark.asyncio
    async def test_cwe_category_evidence(self) -> None:
        result = await provider().lookup(cve_entity("CVE-2021-44228"))
        cats = [e for e in result.evidence if e.type == "category"]
        cwe_cats = [c for c in cats if c.value and c.value.startswith("CWE-")]
        assert len(cwe_cats) > 0
        assert cwe_cats[0].value == "CWE-20"


# --------------------------------------------------------------------------- #
# Relationships
# --------------------------------------------------------------------------- #


class TestRelationships:
    @pytest.mark.asyncio
    async def test_cwe_relationship_present(self) -> None:
        result = await provider().lookup(cve_entity("CVE-2021-44228"))
        weakness_targets = relationship_targets(result, RelationshipTargetType.WEAKNESS)
        assert "CWE-20" in weakness_targets

    @pytest.mark.asyncio
    async def test_cwe_relationship_type(self) -> None:
        result = await provider().lookup(cve_entity("CVE-2021-44228"))
        cwe_rels = [
            r for r in result.relationships if r.target_type is RelationshipTargetType.WEAKNESS
        ]
        assert all(r.relationship is RelationshipType.RELATED_TO for r in cwe_rels)

    @pytest.mark.asyncio
    async def test_heartbleed_cwe_125(self) -> None:
        result = await provider().lookup(cve_entity("CVE-2014-0160"))
        weakness_targets = relationship_targets(result, RelationshipTargetType.WEAKNESS)
        assert "CWE-125" in weakness_targets

    @pytest.mark.asyncio
    async def test_no_relationships_for_cve_without_cwe(self) -> None:
        ds = NvdDataset(
            {
                "vulnerabilities": [
                    {
                        "cve": {
                            "id": "CVE-1900-00001",
                            "published": "1900-01-01",
                            "lastModified": "1900-01-01",
                            "descriptions": [{"lang": "en", "value": "No CWE."}],
                            "metrics": {},
                            "weaknesses": [],
                            "configurations": [],
                            "references": [],
                        }
                    }
                ]
            }
        )
        p = NvdProvider(dataset=ds)
        result = await p.lookup(cve_entity("CVE-1900-00001"))
        assert result.relationships == []


# --------------------------------------------------------------------------- #
# References
# --------------------------------------------------------------------------- #


class TestReferences:
    @pytest.mark.asyncio
    async def test_nvd_canonical_reference_present(self) -> None:
        result = await provider().lookup(cve_entity("CVE-2021-44228"))
        nvd_refs = [r for r in result.references if "nvd.nist.gov" in r.url]
        assert len(nvd_refs) == 1

    @pytest.mark.asyncio
    async def test_vendor_reference_present(self) -> None:
        result = await provider().lookup(cve_entity("CVE-2021-44228"))
        urls = [r.url for r in result.references]
        assert any("logging.apache.org" in u for u in urls)


# --------------------------------------------------------------------------- #
# Metadata
# --------------------------------------------------------------------------- #


class TestMetadata:
    @pytest.mark.asyncio
    async def test_metadata_keyed_with_cve_id(self) -> None:
        result = await provider().lookup(cve_entity("CVE-2021-44228"))
        assert result.metadata.get("cve_id") == "CVE-2021-44228"

    @pytest.mark.asyncio
    async def test_metadata_has_description(self) -> None:
        result = await provider().lookup(cve_entity("CVE-2021-44228"))
        assert "Log4j" in str(result.metadata.get("description", ""))

    @pytest.mark.asyncio
    async def test_metadata_has_published_date(self) -> None:
        result = await provider().lookup(cve_entity("CVE-2021-44228"))
        assert result.metadata.get("published") == "2021-12-10"

    @pytest.mark.asyncio
    async def test_metadata_has_cvss_block(self) -> None:
        result = await provider().lookup(cve_entity("CVE-2021-44228"))
        cvss = result.metadata.get("cvss")
        assert isinstance(cvss, dict)
        assert cvss["base_score"] == 10.0
        assert cvss["base_severity"] == "CRITICAL"
        assert cvss["version"] == "3.1"
        assert "vector_string" in cvss

    @pytest.mark.asyncio
    async def test_metadata_cvss_attack_fields(self) -> None:
        result = await provider().lookup(cve_entity("CVE-2021-44228"))
        cvss = result.metadata.get("cvss", {})
        assert cvss.get("attack_vector") == "Network"
        assert cvss.get("attack_complexity") == "Low"
        assert cvss.get("privileges_required") == "None"
        assert cvss.get("user_interaction") == "None"

    @pytest.mark.asyncio
    async def test_metadata_has_cwes(self) -> None:
        result = await provider().lookup(cve_entity("CVE-2021-44228"))
        cwes = result.metadata.get("cwes")
        assert isinstance(cwes, list)
        assert "CWE-20" in cwes

    @pytest.mark.asyncio
    async def test_metadata_has_affected_products(self) -> None:
        result = await provider().lookup(cve_entity("CVE-2021-44228"))
        products = result.metadata.get("affected_products")
        assert isinstance(products, list)
        assert len(products) > 0
        assert "vendor" in products[0]
        assert "product" in products[0]

    @pytest.mark.asyncio
    async def test_no_reputation_in_result(self) -> None:
        result = await provider().lookup(cve_entity("CVE-2021-44228"))
        assert result.reputation is None


# --------------------------------------------------------------------------- #
# Tags
# --------------------------------------------------------------------------- #


class TestTags:
    @pytest.mark.asyncio
    async def test_tags_include_cve_id(self) -> None:
        result = await provider().lookup(cve_entity("CVE-2021-44228"))
        assert "CVE-2021-44228" in result.tags

    @pytest.mark.asyncio
    async def test_tags_include_severity(self) -> None:
        result = await provider().lookup(cve_entity("CVE-2021-44228"))
        assert "CRITICAL" in result.tags


# --------------------------------------------------------------------------- #
# normalize() surface
# --------------------------------------------------------------------------- #


class TestNormalize:
    @pytest.mark.asyncio
    async def test_normalize_cve_object(self) -> None:
        cve = Cve(
            id="CVE-2099-00001",
            description="Test CVE",
            published="2099-01-01",
            last_modified="2099-01-01",
            vuln_status="Analyzed",
            cvss=CvssMetric(
                version="3.1",
                vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                base_score=9.8,
                base_severity="CRITICAL",
            ),
            cwes=("CWE-89",),
            affected_products=(AffectedProduct("Example", "Widget"),),
            references=(NvdReference(url="https://example.com"),),
        )
        result = await provider().normalize(cve)
        assert result.status == ResultStatus.OK
        assert result.metadata.get("cve_id") == "CVE-2099-00001"

    @pytest.mark.asyncio
    async def test_normalize_rejects_wrong_type(self) -> None:
        with pytest.raises(TypeError):
            await provider().normalize("not-a-cve")


# --------------------------------------------------------------------------- #
# Aggregation compatibility
# --------------------------------------------------------------------------- #


class TestAggregation:
    @pytest.mark.asyncio
    async def test_ok_result_aggregates_cleanly(self) -> None:
        result = await provider().lookup(cve_entity("CVE-2021-44228"))
        aggregated = aggregate([result], entity_type=EntityType.CVE, entity_value="CVE-2021-44228")
        assert len(aggregated.providers) == 1
        assert aggregated.providers[0].status == ResultStatus.OK
        assert aggregated.metadata.get("nvd") is not None

    @pytest.mark.asyncio
    async def test_not_found_aggregates_cleanly(self) -> None:
        result = await provider().lookup(cve_entity("CVE-9999-99999"))
        aggregated = aggregate([result], entity_type=EntityType.CVE, entity_value="CVE-9999-99999")
        assert aggregated.providers[0].status == ResultStatus.NOT_FOUND
