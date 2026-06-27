"""Tests for the CWE reference provider.

All tests run fully offline — no network access. The bundled seed dataset is
exercised directly; a minimal in-memory fixture (MINI_DATA) is used for unit
tests to avoid coupling tests to seed-file content.
"""

from __future__ import annotations

import pytest

from threatlens.entities.models import Entity
from threatlens.entities.types import EntityType, ValidationStatus
from threatlens.providers import (
    RelationshipTargetType,
    RelationshipType,
    ResultStatus,
    aggregate,
)
from threatlens.reference import CweDataset, CweProvider, build_default_reference_registry
from threatlens.reference.cwe.dataset import (
    CweConsequence,
    CweMitigation,
    CweReference,
    CweRelatedWeakness,
)

# --------------------------------------------------------------------------- #
# Minimal in-memory fixture
# --------------------------------------------------------------------------- #

MINI_DATA: dict = {
    "_meta": {
        "version": "4.99-test",
        "release_date": "2099.01.01",
    },
    "weaknesses": [
        {
            "id": 9999,
            "name": "Test Weakness",
            "description": "A synthetic weakness for unit testing.",
            "extended_description": "Extended description for test purposes.",
            "likelihood_of_exploit": "High",
            "applicable_platforms": ["Language: Python", "Technology: Web Server"],
            "common_consequences": [
                {
                    "scope": "Confidentiality",
                    "impact": "Read Application Data",
                    "note": "Sensitive data exposure.",
                },
                {"scope": "Integrity", "impact": "Modify Application Data"},
            ],
            "detection_methods": [
                {"method": "Automated Static Analysis", "description": "Use a linter."},
            ],
            "mitigations": [
                {"phase": "Implementation", "description": "Validate all inputs."},
                {"phase": "Architecture and Design", "description": "Use a framework."},
            ],
            "related_weaknesses": [
                {"cwe_id": 20, "nature": "ChildOf"},
            ],
            "related_attack_patterns": [1, 2, 3],
            "references": [
                {"title": "Test Reference", "url": "https://example.com/cwe9999"},
            ],
        },
        {
            "id": 8888,
            "name": "No CAPEC Weakness",
            "description": "A weakness with no related attack patterns.",
            "extended_description": None,
            "likelihood_of_exploit": None,
            "applicable_platforms": [],
            "common_consequences": [],
            "detection_methods": [],
            "mitigations": [],
            "related_weaknesses": [],
            "related_attack_patterns": [],
            "references": [],
        },
    ],
}


def _mini_dataset() -> CweDataset:
    return CweDataset(MINI_DATA)


def _entity(value: str) -> Entity:
    return Entity(
        type=EntityType.CWE,
        value=value,
        normalized_value=value.upper(),
        confidence=1.0,
        validation=ValidationStatus.VALID,
        possible_matches=[],
    )


# --------------------------------------------------------------------------- #
# TestCweDataset
# --------------------------------------------------------------------------- #


class TestCweDataset:
    def test_loads_from_dict(self) -> None:
        ds = _mini_dataset()
        assert len(ds) == 2

    def test_lookup_by_canonical_id(self) -> None:
        ds = _mini_dataset()
        cwe = ds.lookup("CWE-9999")
        assert cwe is not None
        assert cwe.id == 9999

    def test_lookup_case_insensitive(self) -> None:
        ds = _mini_dataset()
        assert ds.lookup("cwe-9999") is not None
        assert ds.lookup("CWE-9999") is not None

    def test_lookup_bare_number(self) -> None:
        ds = _mini_dataset()
        assert ds.lookup("9999") is not None

    def test_lookup_missing_returns_none(self) -> None:
        ds = _mini_dataset()
        assert ds.lookup("CWE-0") is None

    def test_lookup_invalid_id_returns_none(self) -> None:
        ds = _mini_dataset()
        assert ds.lookup("not-a-cwe") is None

    def test_provenance(self) -> None:
        ds = _mini_dataset()
        prov = ds.provenance
        assert prov.version == "4.99-test"
        assert prov.release_date == "2099.01.01"
        assert prov.last_updated is not None
        assert prov.last_updated.year == 2099

    def test_cwe_id_property(self) -> None:
        ds = _mini_dataset()
        cwe = ds.lookup("CWE-9999")
        assert cwe is not None
        assert cwe.cwe_id == "CWE-9999"


class TestCweDatasetParsing:
    def test_consequences_parsed(self) -> None:
        ds = _mini_dataset()
        cwe = ds.lookup("CWE-9999")
        assert cwe is not None
        assert len(cwe.common_consequences) == 2
        c = cwe.common_consequences[0]
        assert isinstance(c, CweConsequence)
        assert c.scope == "Confidentiality"
        assert c.impact == "Read Application Data"
        assert c.note == "Sensitive data exposure."

    def test_mitigations_parsed(self) -> None:
        ds = _mini_dataset()
        cwe = ds.lookup("CWE-9999")
        assert cwe is not None
        assert len(cwe.mitigations) == 2
        m = cwe.mitigations[0]
        assert isinstance(m, CweMitigation)
        assert m.phase == "Implementation"

    def test_related_weaknesses_parsed(self) -> None:
        ds = _mini_dataset()
        cwe = ds.lookup("CWE-9999")
        assert cwe is not None
        assert len(cwe.related_weaknesses) == 1
        rw = cwe.related_weaknesses[0]
        assert isinstance(rw, CweRelatedWeakness)
        assert rw.cwe_id == 20
        assert rw.nature == "ChildOf"

    def test_capec_ids_parsed(self) -> None:
        ds = _mini_dataset()
        cwe = ds.lookup("CWE-9999")
        assert cwe is not None
        assert cwe.related_attack_patterns == (1, 2, 3)

    def test_capec_deduplication(self) -> None:
        data = {
            "_meta": {},
            "weaknesses": [
                {
                    "id": 1,
                    "name": "Dup",
                    "description": "d",
                    "extended_description": None,
                    "likelihood_of_exploit": None,
                    "applicable_platforms": [],
                    "common_consequences": [],
                    "detection_methods": [],
                    "mitigations": [],
                    "related_weaknesses": [],
                    "related_attack_patterns": [1, 1, 2],
                    "references": [],
                }
            ],
        }
        ds = CweDataset(data)
        cwe = ds.lookup("CWE-1")
        assert cwe is not None
        assert cwe.related_attack_patterns == (1, 2)

    def test_references_parsed(self) -> None:
        ds = _mini_dataset()
        cwe = ds.lookup("CWE-9999")
        assert cwe is not None
        assert len(cwe.references) == 1
        r = cwe.references[0]
        assert isinstance(r, CweReference)
        assert r.url == "https://example.com/cwe9999"

    def test_no_capec_weakness(self) -> None:
        ds = _mini_dataset()
        cwe = ds.lookup("CWE-8888")
        assert cwe is not None
        assert cwe.related_attack_patterns == ()
        assert cwe.likelihood_of_exploit is None


# --------------------------------------------------------------------------- #
# TestBundledDataset
# --------------------------------------------------------------------------- #


class TestBundledDataset:
    def test_bundled_dataset_loads(self) -> None:
        provider = CweProvider()
        assert provider._dataset is not None
        assert len(provider._dataset) > 0

    def test_xss_present(self) -> None:
        provider = CweProvider()
        assert provider._dataset is not None
        cwe = provider._dataset.lookup("CWE-79")
        assert cwe is not None
        assert "Cross-site Scripting" in cwe.name or "XSS" in cwe.name

    def test_sql_injection_present(self) -> None:
        provider = CweProvider()
        assert provider._dataset is not None
        cwe = provider._dataset.lookup("CWE-89")
        assert cwe is not None
        assert "SQL" in cwe.name

    def test_ssrf_present(self) -> None:
        provider = CweProvider()
        assert provider._dataset is not None
        cwe = provider._dataset.lookup("CWE-918")
        assert cwe is not None
        assert "SSRF" in cwe.name or "Server-Side Request Forgery" in cwe.name

    def test_provenance_set(self) -> None:
        provider = CweProvider()
        assert provider._dataset is not None
        prov = provider._dataset.provenance
        assert prov.version is not None
        assert prov.release_date is not None


# --------------------------------------------------------------------------- #
# TestProviderMetadata
# --------------------------------------------------------------------------- #


class TestProviderMetadata:
    def test_name(self) -> None:
        p = CweProvider()
        assert p.name == "cwe"

    def test_display_name(self) -> None:
        p = CweProvider()
        assert p.metadata.display_name == "MITRE CWE"

    def test_supports_cwe_only(self) -> None:
        p = CweProvider()
        assert p.supports(EntityType.CWE)
        assert not p.supports(EntityType.CVE)
        assert not p.supports(EntityType.MITRE_TECHNIQUE)

    def test_registered_in_default_registry(self) -> None:
        registry = build_default_reference_registry()
        assert "cwe" in registry

    def test_enabled_by_default(self) -> None:
        p = CweProvider()
        assert p.enabled is True

    def test_disabled(self) -> None:
        p = CweProvider(enabled=False)
        assert p.enabled is False


# --------------------------------------------------------------------------- #
# TestLookup
# --------------------------------------------------------------------------- #


class TestLookup:
    @pytest.mark.asyncio
    async def test_lookup_known_cwe(self) -> None:
        provider = CweProvider(dataset=_mini_dataset())
        entity = _entity("CWE-9999")
        result = await provider.lookup(entity)
        assert result.status == ResultStatus.OK
        assert result.provider == "cwe"

    @pytest.mark.asyncio
    async def test_lookup_not_found(self) -> None:
        provider = CweProvider(dataset=_mini_dataset())
        entity = _entity("CWE-0000")
        result = await provider.lookup(entity)
        assert result.status == ResultStatus.NOT_FOUND

    @pytest.mark.asyncio
    async def test_lookup_unsupported_entity_type(self) -> None:
        provider = CweProvider(dataset=_mini_dataset())
        entity = Entity(
            type=EntityType.CVE,
            value="CVE-2021-0001",
            normalized_value="CVE-2021-0001",
            confidence=1.0,
            validation=ValidationStatus.VALID,
            possible_matches=[],
        )
        result = await provider.lookup(entity)
        assert result.status == ResultStatus.UNSUPPORTED

    @pytest.mark.asyncio
    async def test_lookup_missing_dataset_returns_error(self) -> None:
        from pathlib import Path

        provider = CweProvider(dataset_path=Path("/nonexistent/cwe.json"))
        entity = _entity("CWE-9999")
        result = await provider.lookup(entity)
        assert result.status == ResultStatus.ERROR
        assert result.error is not None

    @pytest.mark.asyncio
    async def test_safe_lookup_never_raises(self) -> None:
        provider = CweProvider(dataset=_mini_dataset())
        entity = _entity("CWE-9999")
        result = await provider.safe_lookup(entity)
        assert result is not None


# --------------------------------------------------------------------------- #
# TestEvidence
# --------------------------------------------------------------------------- #


class TestEvidence:
    @pytest.mark.asyncio
    async def test_classification_evidence(self) -> None:
        provider = CweProvider(dataset=_mini_dataset())
        result = await provider.lookup(_entity("CWE-9999"))
        types = [e.type for e in result.evidence]
        assert "classification" in types

    @pytest.mark.asyncio
    async def test_classification_summary_format(self) -> None:
        provider = CweProvider(dataset=_mini_dataset())
        result = await provider.lookup(_entity("CWE-9999"))
        clf = next(e for e in result.evidence if e.type == "classification")
        assert "CWE-9999" in clf.summary
        assert "Test Weakness" in clf.summary

    @pytest.mark.asyncio
    async def test_likelihood_category_evidence(self) -> None:
        provider = CweProvider(dataset=_mini_dataset())
        result = await provider.lookup(_entity("CWE-9999"))
        cats = [e for e in result.evidence if e.type == "category"]
        assert any("Likelihood" in e.summary and "High" in e.summary for e in cats)

    @pytest.mark.asyncio
    async def test_platform_evidence(self) -> None:
        provider = CweProvider(dataset=_mini_dataset())
        result = await provider.lookup(_entity("CWE-9999"))
        others = [e.summary for e in result.evidence if e.type == "other"]
        assert any("Language: Python" in s for s in others)

    @pytest.mark.asyncio
    async def test_consequence_evidence(self) -> None:
        provider = CweProvider(dataset=_mini_dataset())
        result = await provider.lookup(_entity("CWE-9999"))
        others = [e.summary for e in result.evidence if e.type == "other"]
        assert any("Consequence" in s and "Confidentiality" in s for s in others)

    @pytest.mark.asyncio
    async def test_detection_method_evidence(self) -> None:
        provider = CweProvider(dataset=_mini_dataset())
        result = await provider.lookup(_entity("CWE-9999"))
        others = [e.summary for e in result.evidence if e.type == "other"]
        assert any("Detection Method" in s and "Automated Static Analysis" in s for s in others)

    @pytest.mark.asyncio
    async def test_no_evidence_for_no_likelihood(self) -> None:
        provider = CweProvider(dataset=_mini_dataset())
        result = await provider.lookup(_entity("CWE-8888"))
        cats = [e for e in result.evidence if e.type == "category"]
        assert not any("Likelihood" in e.summary for e in cats)


# --------------------------------------------------------------------------- #
# TestRelationships
# --------------------------------------------------------------------------- #


class TestRelationships:
    @pytest.mark.asyncio
    async def test_parent_weakness_relationship(self) -> None:
        provider = CweProvider(dataset=_mini_dataset())
        result = await provider.lookup(_entity("CWE-9999"))
        weakness_rels = [
            r
            for r in result.relationships
            if r.target_type == RelationshipTargetType.WEAKNESS
        ]
        assert len(weakness_rels) == 1
        assert weakness_rels[0].target_value == "CWE-20"

    @pytest.mark.asyncio
    async def test_capec_relationships(self) -> None:
        provider = CweProvider(dataset=_mini_dataset())
        result = await provider.lookup(_entity("CWE-9999"))
        capec_rels = [
            r
            for r in result.relationships
            if r.target_type == RelationshipTargetType.ATTACK_PATTERN
        ]
        assert len(capec_rels) == 3
        values = {r.target_value for r in capec_rels}
        assert "CAPEC-1" in values
        assert "CAPEC-2" in values
        assert "CAPEC-3" in values

    @pytest.mark.asyncio
    async def test_relationship_type_is_related_to(self) -> None:
        provider = CweProvider(dataset=_mini_dataset())
        result = await provider.lookup(_entity("CWE-9999"))
        for r in result.relationships:
            assert r.relationship == RelationshipType.RELATED_TO

    @pytest.mark.asyncio
    async def test_no_relationships_for_no_capec_no_parents(self) -> None:
        provider = CweProvider(dataset=_mini_dataset())
        result = await provider.lookup(_entity("CWE-8888"))
        assert result.relationships == []

    @pytest.mark.asyncio
    async def test_xss_capec_relationships(self) -> None:
        provider = CweProvider()
        result = await provider.lookup(_entity("CWE-79"))
        assert result.status == ResultStatus.OK
        capec_rels = [
            r
            for r in result.relationships
            if r.target_type == RelationshipTargetType.ATTACK_PATTERN
        ]
        assert len(capec_rels) > 0


# --------------------------------------------------------------------------- #
# TestReferences
# --------------------------------------------------------------------------- #


class TestReferences:
    @pytest.mark.asyncio
    async def test_canonical_reference_first(self) -> None:
        provider = CweProvider(dataset=_mini_dataset())
        result = await provider.lookup(_entity("CWE-9999"))
        assert len(result.references) >= 1
        first = result.references[0]
        assert "cwe.mitre.org" in first.url
        assert "9999" in first.url

    @pytest.mark.asyncio
    async def test_dataset_references_included(self) -> None:
        provider = CweProvider(dataset=_mini_dataset())
        result = await provider.lookup(_entity("CWE-9999"))
        urls = [r.url for r in result.references]
        assert "https://example.com/cwe9999" in urls

    @pytest.mark.asyncio
    async def test_no_duplicate_canonical_ref(self) -> None:
        provider = CweProvider()
        result = await provider.lookup(_entity("CWE-79"))
        canonical_url = "https://cwe.mitre.org/data/definitions/79.html"
        urls = [r.url for r in result.references]
        assert urls.count(canonical_url) == 1


# --------------------------------------------------------------------------- #
# TestMetadata
# --------------------------------------------------------------------------- #


class TestMetadata:
    @pytest.mark.asyncio
    async def test_cwe_id_in_metadata(self) -> None:
        provider = CweProvider(dataset=_mini_dataset())
        result = await provider.lookup(_entity("CWE-9999"))
        assert result.metadata["cwe_id"] == "CWE-9999"

    @pytest.mark.asyncio
    async def test_name_in_metadata(self) -> None:
        provider = CweProvider(dataset=_mini_dataset())
        result = await provider.lookup(_entity("CWE-9999"))
        assert result.metadata["name"] == "Test Weakness"

    @pytest.mark.asyncio
    async def test_description_in_metadata(self) -> None:
        provider = CweProvider(dataset=_mini_dataset())
        result = await provider.lookup(_entity("CWE-9999"))
        assert "synthetic" in str(result.metadata["description"])

    @pytest.mark.asyncio
    async def test_extended_description_in_metadata(self) -> None:
        provider = CweProvider(dataset=_mini_dataset())
        result = await provider.lookup(_entity("CWE-9999"))
        assert "extended_description" in result.metadata

    @pytest.mark.asyncio
    async def test_likelihood_in_metadata(self) -> None:
        provider = CweProvider(dataset=_mini_dataset())
        result = await provider.lookup(_entity("CWE-9999"))
        assert result.metadata["likelihood_of_exploit"] == "High"

    @pytest.mark.asyncio
    async def test_platforms_in_metadata(self) -> None:
        provider = CweProvider(dataset=_mini_dataset())
        result = await provider.lookup(_entity("CWE-9999"))
        platforms = result.metadata["applicable_platforms"]
        assert "Language: Python" in platforms

    @pytest.mark.asyncio
    async def test_consequences_in_metadata(self) -> None:
        provider = CweProvider(dataset=_mini_dataset())
        result = await provider.lookup(_entity("CWE-9999"))
        consequences = result.metadata["common_consequences"]
        assert len(consequences) == 2
        assert consequences[0]["scope"] == "Confidentiality"

    @pytest.mark.asyncio
    async def test_mitigations_in_metadata(self) -> None:
        provider = CweProvider(dataset=_mini_dataset())
        result = await provider.lookup(_entity("CWE-9999"))
        mitigations = result.metadata["mitigations"]
        assert len(mitigations) == 2
        assert mitigations[0]["phase"] == "Implementation"

    @pytest.mark.asyncio
    async def test_capec_in_metadata(self) -> None:
        provider = CweProvider(dataset=_mini_dataset())
        result = await provider.lookup(_entity("CWE-9999"))
        capecs = result.metadata["related_attack_patterns"]
        assert "CAPEC-1" in capecs
        assert "CAPEC-2" in capecs

    @pytest.mark.asyncio
    async def test_no_reputation(self) -> None:
        provider = CweProvider(dataset=_mini_dataset())
        result = await provider.lookup(_entity("CWE-9999"))
        assert result.reputation is None

    @pytest.mark.asyncio
    async def test_no_extended_description_absent_from_metadata(self) -> None:
        provider = CweProvider(dataset=_mini_dataset())
        result = await provider.lookup(_entity("CWE-8888"))
        assert "extended_description" not in result.metadata


# --------------------------------------------------------------------------- #
# TestTags
# --------------------------------------------------------------------------- #


class TestTags:
    @pytest.mark.asyncio
    async def test_cwe_id_in_tags(self) -> None:
        provider = CweProvider(dataset=_mini_dataset())
        result = await provider.lookup(_entity("CWE-9999"))
        assert "CWE-9999" in result.tags

    @pytest.mark.asyncio
    async def test_likelihood_in_tags(self) -> None:
        provider = CweProvider(dataset=_mini_dataset())
        result = await provider.lookup(_entity("CWE-9999"))
        assert "High" in result.tags

    @pytest.mark.asyncio
    async def test_no_likelihood_tag_when_absent(self) -> None:
        provider = CweProvider(dataset=_mini_dataset())
        result = await provider.lookup(_entity("CWE-8888"))
        assert "CWE-8888" in result.tags
        assert len(result.tags) == 1


# --------------------------------------------------------------------------- #
# TestNormalize
# --------------------------------------------------------------------------- #


class TestNormalize:
    @pytest.mark.asyncio
    async def test_normalize_cwe_object(self) -> None:
        provider = CweProvider(dataset=_mini_dataset())
        ds = _mini_dataset()
        cwe = ds.lookup("CWE-9999")
        assert cwe is not None
        result = await provider.normalize(cwe)
        assert result.status == ResultStatus.OK
        assert result.metadata["cwe_id"] == "CWE-9999"

    @pytest.mark.asyncio
    async def test_normalize_wrong_type_raises(self) -> None:
        provider = CweProvider(dataset=_mini_dataset())
        with pytest.raises(TypeError):
            await provider.normalize({"id": 9999})


# --------------------------------------------------------------------------- #
# TestAggregation
# --------------------------------------------------------------------------- #


class TestAggregation:
    @pytest.mark.asyncio
    async def test_ok_result_aggregates(self) -> None:
        provider = CweProvider(dataset=_mini_dataset())
        result = await provider.lookup(_entity("CWE-9999"))
        assert result.status == ResultStatus.OK
        aggregated = aggregate(
            [result], entity_type=EntityType.CWE, entity_value="CWE-9999"
        )
        assert aggregated.metadata.get("cwe") is not None
        cwe_meta = aggregated.metadata["cwe"]
        assert isinstance(cwe_meta, dict)
        assert cwe_meta["cwe_id"] == "CWE-9999"

    @pytest.mark.asyncio
    async def test_not_found_aggregates_cleanly(self) -> None:
        provider = CweProvider(dataset=_mini_dataset())
        result = await provider.lookup(_entity("CWE-0000"))
        assert result.status == ResultStatus.NOT_FOUND
        aggregated = aggregate(
            [result], entity_type=EntityType.CWE, entity_value="CWE-0000"
        )
        assert aggregated.metadata.get("cwe") is None


# --------------------------------------------------------------------------- #
# TestDetector
# --------------------------------------------------------------------------- #


class TestCweDetector:
    """Tests for CWE detection in the universal entity engine."""

    def test_detects_cwe_79(self) -> None:
        from threatlens.search import detect

        entity = detect("CWE-79")
        assert entity.type == EntityType.CWE
        assert entity.normalized_value == "CWE-79"

    def test_detects_lowercase(self) -> None:
        from threatlens.search import detect

        entity = detect("cwe-89")
        assert entity.type == EntityType.CWE
        assert entity.normalized_value == "CWE-89"

    def test_detects_large_id(self) -> None:
        from threatlens.search import detect

        entity = detect("CWE-918")
        assert entity.type == EntityType.CWE

    def test_cve_not_detected_as_cwe(self) -> None:
        from threatlens.search import detect

        entity = detect("CVE-2021-44228")
        assert entity.type == EntityType.CVE

    def test_bare_number_not_detected_as_cwe(self) -> None:
        from threatlens.search import detect

        entity = detect("79")
        assert entity.type != EntityType.CWE
