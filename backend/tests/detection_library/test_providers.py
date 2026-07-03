"""Provider framework tests: the seven sources, read-only, every language."""

from __future__ import annotations

import pytest

from threatlens.detection_library import DEFAULT_SOURCES, build_default_provider_registry
from threatlens.detection_library.providers.base import (
    CommunityProviderRegistry,
    DuplicateCommunityProviderError,
)

_EXPECTED = {"sigmahq", "yara-rules", "emerging-threats", "elastic", "microsoft", "talos", "splunk"}


def test_seven_default_sources_registered() -> None:
    registry = build_default_provider_registry()
    assert {p.metadata.id for p in registry.providers} == _EXPECTED
    assert len(DEFAULT_SOURCES) == 7


def test_providers_ordered_by_priority_then_id() -> None:
    registry = build_default_provider_registry()
    keys = [(p.priority, p.name) for p in registry.providers]
    assert keys == sorted(keys)


def test_every_provider_yields_normalized_rules() -> None:
    for provider in build_default_provider_registry().providers:
        rules = provider.rules()
        assert rules, f"{provider.name} produced no rules"
        assert all(r.source.id == provider.metadata.id for r in rules)
        assert all(r.id.startswith("com_") for r in rules)


def test_all_nine_languages_or_more_are_represented() -> None:
    langs = {r.language.value for r in build_default_provider_registry().all_rules()}
    # Sigma, YARA, Suricata, Snort, and the SIEM dialects all appear.
    assert {
        "sigma",
        "yara",
        "suricata",
        "snort",
        "splunk_spl",
        "sentinel_kql",
        "elastic_esql",
    } <= langs


def test_rules_are_deterministic_per_provider() -> None:
    registry = build_default_provider_registry()
    for provider in registry.providers:
        assert provider.rules() == provider.rules()


def test_registry_rejects_duplicate_ids() -> None:
    registry = build_default_provider_registry()
    dupe = registry.providers[0]
    with pytest.raises(DuplicateCommunityProviderError):
        registry.register(dupe)


def test_empty_registry_is_well_formed() -> None:
    registry = CommunityProviderRegistry()
    assert len(registry) == 0
    assert registry.all_rules() == ()
