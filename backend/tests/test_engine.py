"""Engine behavior: output contract, confidence, ambiguity, determinism."""

from __future__ import annotations

import pytest

from threatlens.entities.models import Entity
from threatlens.entities.types import EntityType as ET
from threatlens.entities.types import ValidationStatus
from threatlens.search import build_default_engine, detect

EXPECTED_KEYS = {
    "type",
    "value",
    "normalized_value",
    "confidence",
    "validation",
    "possible_matches",
    "routing",
}


def test_output_contract_matches_spec() -> None:
    dumped = detect("185.100.10.15").model_dump(mode="json")
    assert set(dumped) == EXPECTED_KEYS
    assert dumped == {
        "type": "ipv4",
        "value": "185.100.10.15",
        "normalized_value": "185.100.10.15",
        "confidence": 100,
        "validation": "valid",
        "possible_matches": [],
        "routing": {"providers": []},
    }


def test_every_detection_returns_entity() -> None:
    for raw in ["8.8.8.8", "garbage-token", "", "the quick brown fox", "Emotet"]:
        assert isinstance(detect(raw), Entity)


def test_unknown_is_valid_object() -> None:
    e = detect("zzz-not-an-entity-zzz")
    assert e.type == ET.UNKNOWN
    assert e.confidence == 0
    assert e.validation == ValidationStatus.UNVALIDATED
    assert e.value == "zzz-not-an-entity-zzz"
    assert e.possible_matches == []
    assert e.routing.providers == []


def test_empty_input_is_unknown() -> None:
    for raw in ["", "   "]:
        e = detect(raw)
        assert e.type == ET.UNKNOWN
        assert e.value == ""
        assert e.normalized_value == ""


@pytest.mark.parametrize(
    "raw,expected_confidence",
    [
        ("8.8.8.8", 100),  # structural, deterministic
        ("powershell.exe", 100),  # known process
        ("randomtool.exe", 70),  # bare executable extension
        ("Invoke-WebRequest", 95),  # known cmdlet
        ("Stop-Banana", 85),  # approved verb, unknown cmdlet
        ("VirtualAlloc", 95),  # known Windows API
        ("ZwQueryObscureThing", 70),  # native API heuristic
        ("APT29", 95),  # APT pattern
        ("Lazarus", 85),  # named actor alias
        ("Emotet", 80),  # malware family
    ],
)
def test_confidence_values(raw: str, expected_confidence: int) -> None:
    assert detect(raw).confidence == expected_confidence


def test_routing_is_empty_placeholder() -> None:
    # Phase 1.1 never populates routing; the structure exists for Phase 1.2.
    assert detect("8.8.8.8").routing.providers == []


def test_ambiguous_input_surfaces_possible_matches() -> None:
    # "Turla" is both a threat actor and (via Snake) a malware family.
    e = detect("Turla")
    assert e.type == ET.THREAT_ACTOR  # higher-priority match wins as primary
    assert e.normalized_value == "Turla"
    alt_types = {m.type for m in e.possible_matches}
    assert ET.MALWARE_FAMILY in alt_types


def test_unambiguous_input_has_no_possible_matches() -> None:
    assert detect("8.8.8.8").possible_matches == []
    assert detect("d41d8cd98f00b204e9800998ecf8427e").possible_matches == []


def test_detection_is_deterministic() -> None:
    assert detect("8.8.8.8") == detect("8.8.8.8")
    assert detect("Cozy Bear") == detect("Cozy Bear")


def test_registry_has_unique_priorities_and_full_coverage() -> None:
    engine = build_default_engine()
    detectors = engine._registry.detectors  # noqa: SLF001 - test introspection
    priorities = [d.priority for d in detectors]
    assert len(priorities) == len(set(priorities)), "priorities must be unique"
    assert priorities == sorted(priorities), "registry must be priority-ordered"

    covered = {d.entity_type for d in detectors}
    # Every type except the engine-level fallbacks must have a detector.
    fallbacks = {ET.FREETEXT, ET.UNKNOWN, ET.FILE_NAME}
    assert covered == set(ET) - fallbacks


def test_enum_values_are_stable_strings() -> None:
    assert ET.IPV4 == "ipv4"
    assert ET.MITRE_TECHNIQUE == "mitre_technique"
    assert ET.UNKNOWN == "unknown"
