"""Engine behavior: output contract, confidence, ambiguity, fallbacks."""

from __future__ import annotations

from threatlens.entities.types import EntityType as ET
from threatlens.entities.types import ValidationStatus
from threatlens.search import build_default_engine, detect


def test_output_contract_shape() -> None:
    """A detection serializes to the documented Phase 0 output shape."""
    dumped = detect("185.100.10.15").model_dump(mode="json")
    assert dumped == {
        "type": "ipv4",
        "value": "185.100.10.15",
        "normalized_value": "185.100.10.15",
        "confidence": 100,
        "validation": "valid",
        "possible_matches": [],
        "routing": {"providers": []},
    }


def test_unknown_returns_valid_object() -> None:
    entity = detect("asdfghjklqwerty")
    assert entity.type == ET.UNKNOWN
    assert entity.confidence == 0
    assert entity.validation == ValidationStatus.UNVALIDATED
    assert entity.possible_matches == []
    assert entity.routing.providers == []


def test_empty_input_is_unknown() -> None:
    entity = detect("")
    assert entity.type == ET.UNKNOWN
    assert entity.value == ""


def test_multiword_is_freetext() -> None:
    assert detect("how do I analyze this sample").type == ET.FREETEXT


def test_routing_is_empty_placeholder() -> None:
    # Phase 1.1 never populates routing providers.
    for raw in ("8.8.8.8", "google.com", "Emotet", "VirtualAlloc"):
        assert detect(raw).routing.providers == []


def test_confidence_levels() -> None:
    assert detect("8.8.8.8").confidence == 100  # structural, validated
    assert detect("powershell.exe").confidence == 100  # known process
    assert detect("randomtool.exe").confidence == 70  # extension heuristic only
    assert detect("Invoke-WebRequest").confidence == 95  # known cmdlet
    assert detect("Start-Banana").confidence == 85  # approved verb, unknown cmdlet
    assert detect("VirtualAlloc").confidence == 95  # known API
    assert detect("ZwQueryObscureThing").confidence == 70  # native heuristic
    assert detect("APT29").confidence == 95  # APT pattern
    assert detect("Cozy Bear").confidence == 85  # named alias
    assert detect("Emotet").confidence == 80  # malware family


def test_ambiguous_input_surfaces_possible_matches() -> None:
    """A name that is both an actor and a malware family reports both."""
    entity = detect("Turla")
    assert entity.type == ET.THREAT_ACTOR  # highest priority wins
    assert entity.normalized_value == "Turla"
    assert ET.MALWARE_FAMILY in {m.type for m in entity.possible_matches}


def test_unambiguous_input_has_no_possible_matches() -> None:
    assert detect("8.8.8.8").possible_matches == []
    assert detect("d41d8cd98f00b204e9800998ecf8427e").possible_matches == []


def test_detectors_registered_in_priority_order() -> None:
    detectors = build_default_engine()._registry.detectors
    priorities = [d.priority for d in detectors]
    assert priorities == sorted(priorities)
    # URL must precede domain so URLs are not misread as bare domains.
    types = [d.entity_type for d in detectors]
    assert types.index(ET.URL) < types.index(ET.DOMAIN)


def test_value_preserves_defanged_original() -> None:
    entity = detect("185[.]100[.]10[.]15")
    assert entity.value == "185[.]100[.]10[.]15"  # original retained
    assert entity.normalized_value == "185.100.10.15"  # refanged + canonical
    assert entity.type == ET.IPV4
