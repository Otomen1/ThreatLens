"""Tests for the MITRE ATT&CK reference provider (Phase 1.81).

Fully offline and deterministic: the provider loads the bundled curated STIX
subset (or a tiny in-memory bundle) — no network is ever touched. Covers valid
and invalid techniques, sub-techniques, group/software lookups, relationship
extraction, metadata/provenance, the missing-dataset path, unsupported entities,
and aggregation compatibility.
"""

from __future__ import annotations

from pathlib import Path

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
from threatlens.reference import (
    MitreAttackDataset,
    MitreAttackProvider,
    ReferenceCapability,
    build_default_reference_registry,
)
from threatlens.reference.mitre_attack import Group, Software, Technique


def make_entity(entity_type: EntityType, value: str, normalized: str | None = None) -> Entity:
    return Entity(
        type=entity_type,
        value=value,
        normalized_value=normalized or value,
        confidence=100,
        validation=ValidationStatus.VALID,
    )


def technique_entity(value: str, normalized: str | None = None) -> Entity:
    return make_entity(EntityType.MITRE_TECHNIQUE, value, normalized)


def provider() -> MitreAttackProvider:
    """A provider backed by the bundled offline dataset."""
    return MitreAttackProvider()


def target_values(result: IntelligenceResult, target_type: RelationshipTargetType) -> list[str]:
    return [r.target_value for r in result.relationships if r.target_type is target_type]


# A minimal in-memory STIX bundle for dataset-unit and normalize() tests.
MINI_BUNDLE: dict[str, object] = {
    "type": "bundle",
    "objects": [
        {
            "type": "x-mitre-collection",
            "id": "x-mitre-collection--mini",
            "name": "Mini",
            "x_mitre_version": "1.0",
            "modified": "2023-05-04T00:00:00.000Z",
        },
        {
            "type": "attack-pattern",
            "id": "attack-pattern--t",
            "name": "Sample Technique",
            "description": "A sample.",
            "x_mitre_is_subtechnique": False,
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}],
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T0001", "url": "https://x/t"}
            ],
        },
        {
            "type": "intrusion-set",
            "id": "intrusion-set--g",
            "name": "Sample Group",
            "aliases": ["Sample Group", "SG"],
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "G0001", "url": "https://x/g"}
            ],
        },
        {
            "type": "malware",
            "id": "malware--m",
            "name": "Sample Malware",
            "x_mitre_aliases": ["Sample Malware", "SM"],
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "S0001", "url": "https://x/s"}
            ],
        },
        {
            "type": "relationship",
            "id": "relationship--gm",
            "relationship_type": "uses",
            "source_ref": "intrusion-set--g",
            "target_ref": "attack-pattern--t",
        },
    ],
}


# --- offline loading & provenance ------------------------------------------- #


def test_offline_loading_from_bundled_dataset() -> None:
    meta = provider().metadata
    assert meta.name == "mitre_attack"
    assert meta.display_name == "MITRE ATT&CK"
    assert meta.offline is True
    assert meta.source_url == "https://attack.mitre.org"


def test_dataset_version_and_release_date() -> None:
    meta = provider().metadata
    assert meta.dataset_version == "15.1"
    assert meta.release_date == "2024-10-31"
    assert meta.last_updated is not None


def test_supported_types_and_capabilities() -> None:
    p = provider()
    assert p.supports(EntityType.MITRE_TECHNIQUE)
    assert p.supports(EntityType.THREAT_ACTOR)
    assert p.supports(EntityType.MALWARE_FAMILY)
    assert not p.supports(EntityType.IPV4)
    assert p.has_capability(ReferenceCapability.TECHNIQUE)
    assert p.has_capability(ReferenceCapability.SOFTWARE)


# --- techniques ------------------------------------------------------------- #


async def test_valid_technique_lookup() -> None:
    result = await provider().lookup(technique_entity("T1059"))
    assert result.status is ResultStatus.OK
    assert result.provider == "mitre_attack"
    assert result.reputation is None  # reference providers never set reputation
    assert result.metadata["attack_id"] == "T1059"
    assert result.metadata["name"] == "Command and Scripting Interpreter"
    assert "description" in result.metadata


async def test_invalid_technique_is_not_found() -> None:
    result = await provider().lookup(technique_entity("T9999"))
    assert result.status is ResultStatus.NOT_FOUND
    assert result.error is None
    assert result.reputation is None


async def test_lowercase_input_resolves_via_normalized_value() -> None:
    # The detector normalizes to uppercase; the provider keys on normalized_value.
    result = await provider().lookup(technique_entity("t1059", "T1059"))
    assert result.status is ResultStatus.OK
    assert result.metadata["attack_id"] == "T1059"


async def test_subtechnique_lookup_links_to_parent() -> None:
    result = await provider().lookup(technique_entity("T1059.001"))
    assert result.status is ResultStatus.OK
    assert result.metadata["is_subtechnique"] is True
    assert result.metadata["parent_technique"] == "T1059"
    parent_links = [r for r in result.relationships if r.relationship is RelationshipType.PART_OF]
    assert len(parent_links) == 1
    assert parent_links[0].target_type is RelationshipTargetType.ATTACK_PATTERN
    assert parent_links[0].target_value == "T1059"


async def test_parent_technique_lists_subtechniques() -> None:
    result = await provider().lookup(technique_entity("T1059"))
    assert "T1059.001" in result.metadata["sub_techniques"]
    assert "T1059.001" in target_values(result, RelationshipTargetType.ATTACK_PATTERN)


# --- relationship extraction ------------------------------------------------ #


async def test_technique_relationship_extraction() -> None:
    result = await provider().lookup(technique_entity("T1059"))
    assert "APT28" in target_values(result, RelationshipTargetType.THREAT_ACTOR)
    assert "Cobalt Strike" in target_values(result, RelationshipTargetType.TOOL)
    assert "Sample Intrusion Campaign" in target_values(result, RelationshipTargetType.CAMPAIGN)
    # CAPEC and the sub-technique both surface as attack-pattern edges.
    attack_patterns = target_values(result, RelationshipTargetType.ATTACK_PATTERN)
    assert "CAPEC-136" in attack_patterns
    assert "T1059.001" in attack_patterns


async def test_software_relationship_uses_malware_vs_tool_target() -> None:
    # T1059.001 is used by Emotet (malware), so the edge targets a malware family.
    result = await provider().lookup(technique_entity("T1059.001"))
    assert "Emotet" in target_values(result, RelationshipTargetType.MALWARE_FAMILY)


# --- metadata (only fields actually present) -------------------------------- #


async def test_metadata_omits_absent_fields() -> None:
    # T1059 declares permissions; T1105 does not — metadata must reflect that.
    with_perms = await provider().lookup(technique_entity("T1059"))
    without_perms = await provider().lookup(technique_entity("T1105"))
    assert with_perms.metadata["permissions_required"] == ["User", "Administrator", "SYSTEM"]
    assert "permissions_required" not in without_perms.metadata
    assert "parent_technique" not in with_perms.metadata  # top-level technique


async def test_technique_references_and_tags() -> None:
    result = await provider().lookup(technique_entity("T1059"))
    titles = [r.title for r in result.references]
    urls = [r.url for r in result.references]
    assert "T1059: Command and Scripting Interpreter" in titles
    assert "https://attack.mitre.org/techniques/T1059" in urls
    assert any("capec.mitre.org" in u for u in urls)
    assert "Execution" in result.tags
    assert "Windows" in result.tags


async def test_technique_evidence_has_tactic_and_mitigation() -> None:
    result = await provider().lookup(technique_entity("T1059"))
    summaries = [e.summary for e in result.evidence]
    assert any(s.startswith("Tactic:") for s in summaries)
    assert any("Mitigation: M1038" in s for s in summaries)
    assert any(e.type.value == "detection" for e in result.evidence)


# --- groups (threat actors) & software (malware families) ------------------- #


async def test_threat_actor_group_lookup() -> None:
    result = await provider().lookup(make_entity(EntityType.THREAT_ACTOR, "APT28"))
    assert result.status is ResultStatus.OK
    assert result.reputation is None
    assert result.metadata["attack_id"] == "G0007"
    assert "T1059" in result.metadata["techniques"]
    assert "T1059" in target_values(result, RelationshipTargetType.ATTACK_PATTERN)


async def test_group_resolves_by_alias() -> None:
    # "Fancy Bear" is an alias of APT28 (G0007).
    result = await provider().lookup(
        make_entity(EntityType.THREAT_ACTOR, "Fancy Bear", "Fancy Bear")
    )
    assert result.status is ResultStatus.OK
    assert result.metadata["attack_id"] == "G0007"


async def test_malware_family_software_lookup() -> None:
    result = await provider().lookup(make_entity(EntityType.MALWARE_FAMILY, "Emotet"))
    assert result.status is ResultStatus.OK
    assert result.reputation is None
    assert result.metadata["attack_id"] == "S0367"
    assert result.metadata["is_tool"] is False
    assert "T1059.001" in target_values(result, RelationshipTargetType.ATTACK_PATTERN)


async def test_unknown_group_is_not_found() -> None:
    result = await provider().lookup(make_entity(EntityType.THREAT_ACTOR, "APT9999"))
    assert result.status is ResultStatus.NOT_FOUND


# --- unsupported / missing dataset ------------------------------------------ #


async def test_unsupported_entity_type() -> None:
    result = await provider().lookup(make_entity(EntityType.IPV4, "8.8.8.8"))
    assert result.status is ResultStatus.UNSUPPORTED
    assert result.reputation is None


async def test_missing_dataset_returns_structured_error() -> None:
    p = MitreAttackProvider(dataset_path=Path("/nonexistent/attack.json"))
    result = await p.lookup(technique_entity("T1059"))
    assert result.status is ResultStatus.ERROR
    assert result.error is not None
    assert result.reputation is None


def test_missing_dataset_metadata_is_safe() -> None:
    # Metadata must never crash even when the dataset failed to load.
    meta = MitreAttackProvider(dataset_path=Path("/nonexistent/attack.json")).metadata
    assert meta.offline is True
    assert meta.dataset_version is None
    assert meta.last_updated is None


async def test_safe_lookup_returns_result_without_raising() -> None:
    result = await provider().safe_lookup(technique_entity("T1059"))
    assert result.status is ResultStatus.OK


# --- registration ----------------------------------------------------------- #


def test_registered_in_default_reference_registry() -> None:
    registry = build_default_reference_registry()
    assert "mitre_attack" in registry
    assert "mitre_attack" in {p.name for p in registry.providers}


# --- dataset unit & normalize() --------------------------------------------- #


def test_dataset_indexes_in_isolation() -> None:
    dataset = MitreAttackDataset.from_bundle(MINI_BUNDLE)
    assert dataset.provenance.version == "1.0"
    assert dataset.provenance.release_date == "2023-05-04"

    technique = dataset.technique("T0001")
    assert technique is not None
    assert technique.name == "Sample Technique"
    assert "Sample Group" in [g.name for g in technique.groups]

    # Groups and software resolve by name and by alias.
    assert dataset.group("sample group") is not None
    assert dataset.group("SG") is not None
    assert dataset.software("sm") is not None
    assert dataset.technique("T9999") is None


async def test_normalize_accepts_resolved_views() -> None:
    dataset = MitreAttackDataset.from_bundle(MINI_BUNDLE)
    p = MitreAttackProvider(dataset=dataset)

    technique = dataset.technique("T0001")
    assert isinstance(technique, Technique)
    result = await p.normalize(technique)
    assert result.entity_type is EntityType.MITRE_TECHNIQUE
    assert result.entity_value == "T0001"
    assert result.reputation is None

    group = dataset.group("Sample Group")
    assert isinstance(group, Group)
    assert (await p.normalize(group)).entity_type is EntityType.THREAT_ACTOR

    software = dataset.software("Sample Malware")
    assert isinstance(software, Software)
    assert (await p.normalize(software)).entity_type is EntityType.MALWARE_FAMILY


async def test_normalize_rejects_unknown_input() -> None:
    with pytest.raises(TypeError):
        await provider().normalize(object())


# --- aggregation compatibility ---------------------------------------------- #


async def test_reference_result_flows_through_aggregate() -> None:
    # The future combined document consumes reference results via the existing
    # aggregation engine — no new engine. A single reference result aggregates.
    result = await provider().lookup(technique_entity("T1059"))
    aggregated = aggregate([result], entity_type=EntityType.MITRE_TECHNIQUE, entity_value="T1059")
    assert [p.provider for p in aggregated.providers] == ["mitre_attack"]
    assert aggregated.providers[0].reputation is None  # carried through, never set
    assert len(aggregated.relationships) > 0
    assert len(aggregated.references) > 0
