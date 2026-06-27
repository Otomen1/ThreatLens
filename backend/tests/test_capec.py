"""Tests for the CAPEC reference provider.

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
from threatlens.reference import CapecDataset, CapecProvider, build_default_reference_registry
from threatlens.reference.capec.dataset import (
    CapecAttackStep,
    CapecRelatedPattern,
    CapecSkill,
)

# --------------------------------------------------------------------------- #
# Minimal in-memory fixture
# --------------------------------------------------------------------------- #

MINI_DATA: dict = {
    "_meta": {
        "version": "3.99-test",
        "release_date": "2099.01.01",
    },
    "attack_patterns": [
        {
            "id": 9999,
            "name": "Test Attack Pattern",
            "abstraction": "Standard",
            "description": "A synthetic attack pattern for unit testing.",
            "extended_description": "Extended description for test purposes.",
            "typical_severity": "High",
            "likelihood_of_attack": "Medium",
            "prerequisites": ["Prerequisite one.", "Prerequisite two."],
            "skills_required": [
                {"level": "Low", "description": "Basic skill."},
                {"level": "High"},
            ],
            "resources_required": ["A test client."],
            "indicators": ["Indicator one.", "Indicator two."],
            "execution_flow": [
                {"step": 1, "phase": "Explore", "description": "Explore the target."},
                {"step": 2, "phase": "Exploit", "description": "Exploit the target."},
            ],
            "mitigations": ["Mitigation one.", "Mitigation two."],
            "related_weaknesses": [89, 89, 79],
            "related_attack_patterns": [{"capec_id": 7, "nature": "ChildOf"}],
            "related_techniques": ["T1059", "t1059", "T1105"],
            "references": [{"title": "Test Reference", "url": "https://example.com/capec9999"}],
        },
        {
            "id": 8888,
            "name": "Minimal Pattern",
            "description": "A pattern with no optional fields.",
            "extended_description": None,
            "abstraction": None,
            "typical_severity": None,
            "likelihood_of_attack": None,
            "prerequisites": [],
            "skills_required": [],
            "resources_required": [],
            "indicators": [],
            "execution_flow": [],
            "mitigations": [],
            "related_weaknesses": [],
            "related_attack_patterns": [],
            "related_techniques": [],
            "references": [],
        },
    ],
}


def _mini_dataset() -> CapecDataset:
    return CapecDataset(MINI_DATA)


def _entity(value: str) -> Entity:
    return Entity(
        type=EntityType.CAPEC,
        value=value,
        normalized_value=value.upper(),
        confidence=1.0,
        validation=ValidationStatus.VALID,
        possible_matches=[],
    )


# --------------------------------------------------------------------------- #
# TestCapecDataset
# --------------------------------------------------------------------------- #


class TestCapecDataset:
    def test_loads_from_dict(self) -> None:
        ds = _mini_dataset()
        assert len(ds) == 2

    def test_lookup_by_canonical_id(self) -> None:
        ds = _mini_dataset()
        capec = ds.lookup("CAPEC-9999")
        assert capec is not None
        assert capec.id == 9999

    def test_lookup_case_insensitive(self) -> None:
        ds = _mini_dataset()
        assert ds.lookup("capec-9999") is not None
        assert ds.lookup("CAPEC-9999") is not None

    def test_lookup_bare_number(self) -> None:
        ds = _mini_dataset()
        assert ds.lookup("9999") is not None

    def test_lookup_missing_returns_none(self) -> None:
        ds = _mini_dataset()
        assert ds.lookup("CAPEC-0") is None

    def test_lookup_invalid_id_returns_none(self) -> None:
        ds = _mini_dataset()
        assert ds.lookup("not-a-capec") is None

    def test_provenance(self) -> None:
        ds = _mini_dataset()
        prov = ds.provenance
        assert prov.version == "3.99-test"
        assert prov.release_date == "2099.01.01"
        assert prov.last_updated is not None
        assert prov.last_updated.year == 2099

    def test_capec_id_property(self) -> None:
        ds = _mini_dataset()
        capec = ds.lookup("CAPEC-9999")
        assert capec is not None
        assert capec.capec_id == "CAPEC-9999"


class TestCapecDatasetParsing:
    def test_skills_parsed(self) -> None:
        ds = _mini_dataset()
        capec = ds.lookup("CAPEC-9999")
        assert capec is not None
        assert len(capec.skills_required) == 2
        s = capec.skills_required[0]
        assert isinstance(s, CapecSkill)
        assert s.level == "Low"
        assert s.description == "Basic skill."
        assert capec.skills_required[1].description is None

    def test_execution_flow_parsed(self) -> None:
        ds = _mini_dataset()
        capec = ds.lookup("CAPEC-9999")
        assert capec is not None
        assert len(capec.execution_flow) == 2
        step = capec.execution_flow[0]
        assert isinstance(step, CapecAttackStep)
        assert step.step == 1
        assert step.phase == "Explore"

    def test_related_patterns_parsed(self) -> None:
        ds = _mini_dataset()
        capec = ds.lookup("CAPEC-9999")
        assert capec is not None
        assert len(capec.related_attack_patterns) == 1
        rp = capec.related_attack_patterns[0]
        assert isinstance(rp, CapecRelatedPattern)
        assert rp.capec_id == 7
        assert rp.nature == "ChildOf"

    def test_related_weaknesses_deduplicated(self) -> None:
        ds = _mini_dataset()
        capec = ds.lookup("CAPEC-9999")
        assert capec is not None
        assert capec.related_weaknesses == (89, 79)

    def test_related_techniques_deduplicated_and_uppercased(self) -> None:
        ds = _mini_dataset()
        capec = ds.lookup("CAPEC-9999")
        assert capec is not None
        assert capec.related_techniques == ("T1059", "T1105")

    def test_references_parsed(self) -> None:
        ds = _mini_dataset()
        capec = ds.lookup("CAPEC-9999")
        assert capec is not None
        assert len(capec.references) == 1
        assert capec.references[0].url == "https://example.com/capec9999"

    def test_minimal_pattern(self) -> None:
        ds = _mini_dataset()
        capec = ds.lookup("CAPEC-8888")
        assert capec is not None
        assert capec.typical_severity is None
        assert capec.related_weaknesses == ()
        assert capec.related_techniques == ()
        assert capec.execution_flow == ()


# --------------------------------------------------------------------------- #
# TestBundledDataset
# --------------------------------------------------------------------------- #


class TestBundledDataset:
    def test_bundled_dataset_loads(self) -> None:
        provider = CapecProvider()
        ds = provider._ensure_dataset()
        assert ds is not None
        assert len(ds) > 0

    def test_sql_injection_present(self) -> None:
        provider = CapecProvider()
        ds = provider._ensure_dataset()
        assert ds is not None
        capec = ds.lookup("CAPEC-66")
        assert capec is not None
        assert "SQL Injection" in capec.name

    @pytest.mark.parametrize("capec_id", ["CAPEC-100", "CAPEC-136", "CAPEC-242"])
    def test_task_examples_present(self, capec_id: str) -> None:
        provider = CapecProvider()
        ds = provider._ensure_dataset()
        assert ds is not None
        assert ds.lookup(capec_id) is not None

    def test_code_injection_maps_to_attack_technique(self) -> None:
        provider = CapecProvider()
        ds = provider._ensure_dataset()
        assert ds is not None
        capec = ds.lookup("CAPEC-242")
        assert capec is not None
        assert "T1059" in capec.related_techniques

    def test_provenance_set(self) -> None:
        provider = CapecProvider()
        ds = provider._ensure_dataset()
        assert ds is not None
        prov = ds.provenance
        assert prov.version is not None
        assert prov.release_date is not None


# --------------------------------------------------------------------------- #
# TestProviderMetadata
# --------------------------------------------------------------------------- #


class TestProviderMetadata:
    def test_name(self) -> None:
        assert CapecProvider().name == "capec"

    def test_display_name(self) -> None:
        assert CapecProvider().metadata.display_name == "MITRE CAPEC"

    def test_supports_capec_only(self) -> None:
        p = CapecProvider()
        assert p.supports(EntityType.CAPEC)
        assert not p.supports(EntityType.CWE)
        assert not p.supports(EntityType.MITRE_TECHNIQUE)

    def test_registered_in_default_registry(self) -> None:
        registry = build_default_reference_registry()
        assert "capec" in registry

    def test_enabled_by_default(self) -> None:
        assert CapecProvider().enabled is True

    def test_disabled(self) -> None:
        assert CapecProvider(enabled=False).enabled is False


# --------------------------------------------------------------------------- #
# TestLazyLoading
# --------------------------------------------------------------------------- #


class TestLazyLoading:
    def test_not_loaded_at_construction(self) -> None:
        provider = CapecProvider()
        assert provider._loaded is False
        assert provider._dataset is None

    def test_metadata_does_not_force_load(self) -> None:
        provider = CapecProvider()
        _ = provider.metadata
        assert provider._loaded is False
        assert provider._dataset is None

    def test_injected_dataset_is_loaded(self) -> None:
        provider = CapecProvider(dataset=_mini_dataset())
        assert provider._loaded is True
        assert provider._dataset is not None

    @pytest.mark.asyncio
    async def test_dataset_loaded_after_lookup(self) -> None:
        provider = CapecProvider()
        await provider.lookup(_entity("CAPEC-66"))
        assert provider._loaded is True
        assert provider._dataset is not None

    @pytest.mark.asyncio
    async def test_metadata_provenance_after_load(self) -> None:
        provider = CapecProvider()
        assert provider.metadata.dataset_version is None
        await provider.lookup(_entity("CAPEC-66"))
        assert provider.metadata.dataset_version is not None


# --------------------------------------------------------------------------- #
# TestLookup
# --------------------------------------------------------------------------- #


class TestLookup:
    @pytest.mark.asyncio
    async def test_lookup_known(self) -> None:
        provider = CapecProvider(dataset=_mini_dataset())
        result = await provider.lookup(_entity("CAPEC-9999"))
        assert result.status == ResultStatus.OK
        assert result.provider == "capec"

    @pytest.mark.asyncio
    async def test_lookup_not_found(self) -> None:
        provider = CapecProvider(dataset=_mini_dataset())
        result = await provider.lookup(_entity("CAPEC-0000"))
        assert result.status == ResultStatus.NOT_FOUND

    @pytest.mark.asyncio
    async def test_lookup_unsupported_entity_type(self) -> None:
        provider = CapecProvider(dataset=_mini_dataset())
        entity = Entity(
            type=EntityType.CWE,
            value="CWE-79",
            normalized_value="CWE-79",
            confidence=1.0,
            validation=ValidationStatus.VALID,
            possible_matches=[],
        )
        result = await provider.lookup(entity)
        assert result.status == ResultStatus.UNSUPPORTED

    @pytest.mark.asyncio
    async def test_lookup_missing_dataset_returns_error(self) -> None:
        from pathlib import Path

        provider = CapecProvider(dataset_path=Path("/nonexistent/capec.json"))
        result = await provider.lookup(_entity("CAPEC-9999"))
        assert result.status == ResultStatus.ERROR
        assert result.error is not None

    @pytest.mark.asyncio
    async def test_lookup_corrupted_dataset_returns_error(self, tmp_path) -> None:
        bad = tmp_path / "capec.json"
        bad.write_text("{ this is not valid json", encoding="utf-8")
        provider = CapecProvider(dataset_path=bad)
        result = await provider.lookup(_entity("CAPEC-9999"))
        assert result.status == ResultStatus.ERROR
        assert result.error is not None

    @pytest.mark.asyncio
    async def test_safe_lookup_never_raises(self) -> None:
        provider = CapecProvider(dataset=_mini_dataset())
        result = await provider.safe_lookup(_entity("CAPEC-9999"))
        assert result is not None


# --------------------------------------------------------------------------- #
# TestEvidence
# --------------------------------------------------------------------------- #


class TestEvidence:
    @pytest.mark.asyncio
    async def test_classification_evidence(self) -> None:
        provider = CapecProvider(dataset=_mini_dataset())
        result = await provider.lookup(_entity("CAPEC-9999"))
        clf = next(e for e in result.evidence if e.type == "classification")
        assert "CAPEC-9999" in clf.summary
        assert "Test Attack Pattern" in clf.summary

    @pytest.mark.asyncio
    async def test_severity_category_evidence(self) -> None:
        provider = CapecProvider(dataset=_mini_dataset())
        result = await provider.lookup(_entity("CAPEC-9999"))
        cats = [e for e in result.evidence if e.type == "category"]
        assert any("Severity" in e.summary and "High" in e.summary for e in cats)

    @pytest.mark.asyncio
    async def test_likelihood_category_evidence(self) -> None:
        provider = CapecProvider(dataset=_mini_dataset())
        result = await provider.lookup(_entity("CAPEC-9999"))
        cats = [e for e in result.evidence if e.type == "category"]
        assert any("Likelihood" in e.summary and "Medium" in e.summary for e in cats)

    @pytest.mark.asyncio
    async def test_indicators_detection_evidence(self) -> None:
        provider = CapecProvider(dataset=_mini_dataset())
        result = await provider.lookup(_entity("CAPEC-9999"))
        det = [e for e in result.evidence if e.type == "detection"]
        assert len(det) == 1
        assert det[0].value is not None
        assert "Indicator one." in det[0].value

    @pytest.mark.asyncio
    async def test_mitigation_evidence_prefixed(self) -> None:
        provider = CapecProvider(dataset=_mini_dataset())
        result = await provider.lookup(_entity("CAPEC-9999"))
        others = [e.summary for e in result.evidence if e.type == "other"]
        assert any(s.startswith("Mitigation:") and "Mitigation one." in s for s in others)

    @pytest.mark.asyncio
    async def test_prerequisite_evidence(self) -> None:
        provider = CapecProvider(dataset=_mini_dataset())
        result = await provider.lookup(_entity("CAPEC-9999"))
        others = [e.summary for e in result.evidence if e.type == "other"]
        assert any("Prerequisite:" in s for s in others)

    @pytest.mark.asyncio
    async def test_execution_step_evidence(self) -> None:
        provider = CapecProvider(dataset=_mini_dataset())
        result = await provider.lookup(_entity("CAPEC-9999"))
        others = [e.summary for e in result.evidence if e.type == "other"]
        assert any("Execution Step" in s and "Explore" in s for s in others)

    @pytest.mark.asyncio
    async def test_no_detection_evidence_when_no_indicators(self) -> None:
        provider = CapecProvider(dataset=_mini_dataset())
        result = await provider.lookup(_entity("CAPEC-8888"))
        det = [e for e in result.evidence if e.type == "detection"]
        assert det == []


# --------------------------------------------------------------------------- #
# TestRelationships
# --------------------------------------------------------------------------- #


class TestRelationships:
    @pytest.mark.asyncio
    async def test_weakness_relationships(self) -> None:
        provider = CapecProvider(dataset=_mini_dataset())
        result = await provider.lookup(_entity("CAPEC-9999"))
        weakness_rels = [
            r for r in result.relationships if r.target_type == RelationshipTargetType.WEAKNESS
        ]
        values = {r.target_value for r in weakness_rels}
        assert values == {"CWE-89", "CWE-79"}
        assert all(r.relationship == RelationshipType.EXPLOITS for r in weakness_rels)

    @pytest.mark.asyncio
    async def test_technique_relationships(self) -> None:
        provider = CapecProvider(dataset=_mini_dataset())
        result = await provider.lookup(_entity("CAPEC-9999"))
        tech_rels = [
            r
            for r in result.relationships
            if r.target_type == RelationshipTargetType.ATTACK_PATTERN
            and r.target_value.startswith("T")
        ]
        values = {r.target_value for r in tech_rels}
        assert "T1059" in values
        assert "T1105" in values

    @pytest.mark.asyncio
    async def test_related_capec_relationships(self) -> None:
        provider = CapecProvider(dataset=_mini_dataset())
        result = await provider.lookup(_entity("CAPEC-9999"))
        capec_rels = [
            r
            for r in result.relationships
            if r.target_type == RelationshipTargetType.ATTACK_PATTERN
            and r.target_value.startswith("CAPEC-")
        ]
        assert len(capec_rels) == 1
        assert capec_rels[0].target_value == "CAPEC-7"
        assert capec_rels[0].description == "ChildOf"

    @pytest.mark.asyncio
    async def test_no_relationships_for_minimal(self) -> None:
        provider = CapecProvider(dataset=_mini_dataset())
        result = await provider.lookup(_entity("CAPEC-8888"))
        assert result.relationships == []

    @pytest.mark.asyncio
    async def test_bundled_code_injection_bridges_cwe_and_attack(self) -> None:
        provider = CapecProvider()
        result = await provider.lookup(_entity("CAPEC-242"))
        assert result.status == ResultStatus.OK
        weakness = {
            r.target_value
            for r in result.relationships
            if r.target_type == RelationshipTargetType.WEAKNESS
        }
        techniques = {
            r.target_value
            for r in result.relationships
            if r.target_type == RelationshipTargetType.ATTACK_PATTERN
            and r.target_value.startswith("T")
        }
        assert "CWE-94" in weakness
        assert "T1059" in techniques


# --------------------------------------------------------------------------- #
# TestReferences
# --------------------------------------------------------------------------- #


class TestReferences:
    @pytest.mark.asyncio
    async def test_canonical_reference_first(self) -> None:
        provider = CapecProvider(dataset=_mini_dataset())
        result = await provider.lookup(_entity("CAPEC-9999"))
        assert len(result.references) >= 1
        first = result.references[0]
        assert "capec.mitre.org" in first.url
        assert "9999" in first.url

    @pytest.mark.asyncio
    async def test_dataset_references_included(self) -> None:
        provider = CapecProvider(dataset=_mini_dataset())
        result = await provider.lookup(_entity("CAPEC-9999"))
        urls = [r.url for r in result.references]
        assert "https://example.com/capec9999" in urls

    @pytest.mark.asyncio
    async def test_no_duplicate_canonical_ref(self) -> None:
        provider = CapecProvider()
        result = await provider.lookup(_entity("CAPEC-66"))
        canonical = "https://capec.mitre.org/data/definitions/66.html"
        urls = [r.url for r in result.references]
        assert urls.count(canonical) == 1


# --------------------------------------------------------------------------- #
# TestMetadata
# --------------------------------------------------------------------------- #


class TestMetadata:
    @pytest.mark.asyncio
    async def test_core_metadata(self) -> None:
        provider = CapecProvider(dataset=_mini_dataset())
        result = await provider.lookup(_entity("CAPEC-9999"))
        assert result.metadata["capec_id"] == "CAPEC-9999"
        assert result.metadata["name"] == "Test Attack Pattern"
        assert "synthetic" in str(result.metadata["description"])

    @pytest.mark.asyncio
    async def test_severity_and_likelihood_metadata(self) -> None:
        provider = CapecProvider(dataset=_mini_dataset())
        result = await provider.lookup(_entity("CAPEC-9999"))
        assert result.metadata["typical_severity"] == "High"
        assert result.metadata["likelihood_of_attack"] == "Medium"

    @pytest.mark.asyncio
    async def test_related_weaknesses_metadata(self) -> None:
        provider = CapecProvider(dataset=_mini_dataset())
        result = await provider.lookup(_entity("CAPEC-9999"))
        weaknesses = result.metadata["related_weaknesses"]
        assert "CWE-89" in weaknesses
        assert "CWE-79" in weaknesses

    @pytest.mark.asyncio
    async def test_related_techniques_metadata(self) -> None:
        provider = CapecProvider(dataset=_mini_dataset())
        result = await provider.lookup(_entity("CAPEC-9999"))
        assert result.metadata["related_techniques"] == ["T1059", "T1105"]

    @pytest.mark.asyncio
    async def test_related_attack_patterns_metadata(self) -> None:
        provider = CapecProvider(dataset=_mini_dataset())
        result = await provider.lookup(_entity("CAPEC-9999"))
        assert result.metadata["related_attack_patterns"] == ["CAPEC-7"]

    @pytest.mark.asyncio
    async def test_execution_flow_metadata(self) -> None:
        provider = CapecProvider(dataset=_mini_dataset())
        result = await provider.lookup(_entity("CAPEC-9999"))
        flow = result.metadata["execution_flow"]
        assert len(flow) == 2
        assert flow[0]["phase"] == "Explore"

    @pytest.mark.asyncio
    async def test_skills_metadata(self) -> None:
        provider = CapecProvider(dataset=_mini_dataset())
        result = await provider.lookup(_entity("CAPEC-9999"))
        skills = result.metadata["skills_required"]
        assert skills[0]["level"] == "Low"

    @pytest.mark.asyncio
    async def test_no_reputation(self) -> None:
        provider = CapecProvider(dataset=_mini_dataset())
        result = await provider.lookup(_entity("CAPEC-9999"))
        assert result.reputation is None

    @pytest.mark.asyncio
    async def test_optional_fields_absent_for_minimal(self) -> None:
        provider = CapecProvider(dataset=_mini_dataset())
        result = await provider.lookup(_entity("CAPEC-8888"))
        assert "typical_severity" not in result.metadata
        assert "related_weaknesses" not in result.metadata
        assert "execution_flow" not in result.metadata


# --------------------------------------------------------------------------- #
# TestTags
# --------------------------------------------------------------------------- #


class TestTags:
    @pytest.mark.asyncio
    async def test_capec_id_in_tags(self) -> None:
        provider = CapecProvider(dataset=_mini_dataset())
        result = await provider.lookup(_entity("CAPEC-9999"))
        assert "CAPEC-9999" in result.tags

    @pytest.mark.asyncio
    async def test_severity_in_tags(self) -> None:
        provider = CapecProvider(dataset=_mini_dataset())
        result = await provider.lookup(_entity("CAPEC-9999"))
        assert "High" in result.tags

    @pytest.mark.asyncio
    async def test_no_severity_tag_when_absent(self) -> None:
        provider = CapecProvider(dataset=_mini_dataset())
        result = await provider.lookup(_entity("CAPEC-8888"))
        assert result.tags == ["CAPEC-8888"]


# --------------------------------------------------------------------------- #
# TestNormalize
# --------------------------------------------------------------------------- #


class TestNormalize:
    @pytest.mark.asyncio
    async def test_normalize_capec_object(self) -> None:
        provider = CapecProvider(dataset=_mini_dataset())
        ds = _mini_dataset()
        capec = ds.lookup("CAPEC-9999")
        assert capec is not None
        result = await provider.normalize(capec)
        assert result.status == ResultStatus.OK
        assert result.metadata["capec_id"] == "CAPEC-9999"

    @pytest.mark.asyncio
    async def test_normalize_wrong_type_raises(self) -> None:
        provider = CapecProvider(dataset=_mini_dataset())
        with pytest.raises(TypeError):
            await provider.normalize({"id": 9999})


# --------------------------------------------------------------------------- #
# TestAggregation
# --------------------------------------------------------------------------- #


class TestAggregation:
    @pytest.mark.asyncio
    async def test_ok_result_aggregates(self) -> None:
        provider = CapecProvider(dataset=_mini_dataset())
        result = await provider.lookup(_entity("CAPEC-9999"))
        aggregated = aggregate([result], entity_type=EntityType.CAPEC, entity_value="CAPEC-9999")
        cap_meta = aggregated.metadata.get("capec")
        assert isinstance(cap_meta, dict)
        assert cap_meta["capec_id"] == "CAPEC-9999"

    @pytest.mark.asyncio
    async def test_not_found_aggregates_cleanly(self) -> None:
        provider = CapecProvider(dataset=_mini_dataset())
        result = await provider.lookup(_entity("CAPEC-0000"))
        aggregated = aggregate([result], entity_type=EntityType.CAPEC, entity_value="CAPEC-0000")
        assert aggregated.metadata.get("capec") is None


# --------------------------------------------------------------------------- #
# TestCapecDetector
# --------------------------------------------------------------------------- #


class TestCapecDetector:
    """Tests for CAPEC detection in the universal entity engine."""

    def test_detects_capec_66(self) -> None:
        from threatlens.search import detect

        entity = detect("CAPEC-66")
        assert entity.type == EntityType.CAPEC
        assert entity.normalized_value == "CAPEC-66"

    def test_detects_lowercase(self) -> None:
        from threatlens.search import detect

        entity = detect("capec-242")
        assert entity.type == EntityType.CAPEC
        assert entity.normalized_value == "CAPEC-242"

    def test_detects_large_id(self) -> None:
        from threatlens.search import detect

        entity = detect("CAPEC-664")
        assert entity.type == EntityType.CAPEC

    def test_cve_not_detected_as_capec(self) -> None:
        from threatlens.search import detect

        entity = detect("CVE-2021-44228")
        assert entity.type == EntityType.CVE

    def test_cwe_not_detected_as_capec(self) -> None:
        from threatlens.search import detect

        entity = detect("CWE-79")
        assert entity.type == EntityType.CWE

    def test_bare_number_not_detected_as_capec(self) -> None:
        from threatlens.search import detect

        entity = detect("66")
        assert entity.type != EntityType.CAPEC
