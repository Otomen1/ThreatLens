"""Licensing tests: attribution preserved, content redistribution respected."""

from __future__ import annotations

from threatlens.detection_library import build_default_provider_registry
from threatlens.detection_library.types import LicenseSupport

_RULES = build_default_provider_registry().all_rules()
_BY_SOURCE = {r.source.id: r for r in _RULES}


def test_every_rule_carries_full_attribution() -> None:
    for rule in _RULES:
        assert rule.source.repository
        assert rule.source.url
        assert rule.license.spdx_id
        assert rule.license.name
        assert rule.author.name
        assert rule.version.content_hash
        assert rule.url


def test_known_licenses_are_mapped_per_repository() -> None:
    assert _BY_SOURCE["sigmahq"].license.spdx_id == "DRL-1.1"
    assert _BY_SOURCE["yara-rules"].license.spdx_id == "GPL-2.0-only"
    assert _BY_SOURCE["emerging-threats"].license.spdx_id == "BSD-3-Clause"
    assert _BY_SOURCE["microsoft"].license.spdx_id == "MIT"
    assert _BY_SOURCE["splunk"].license.spdx_id == "Apache-2.0"


def test_permissive_and_copyleft_content_is_redistributable() -> None:
    for source_id in ("sigmahq", "yara-rules", "emerging-threats", "microsoft", "splunk", "talos"):
        rule = _BY_SOURCE[source_id]
        assert rule.license.redistributable
        assert rule.content is not None  # body shown with attribution


def test_restricted_license_withholds_content_with_a_documented_note() -> None:
    rule = _BY_SOURCE["elastic"]
    assert rule.license.support is LicenseSupport.RESTRICTED
    assert not rule.license.redistributable
    assert rule.content is None  # body withheld
    assert rule.license.note  # the reason is documented
    # ...but attribution + link survive so the analyst can view it upstream.
    assert rule.url
    assert rule.author.name


def test_content_is_never_rewritten() -> None:
    # A redistributable rule's stored body matches its content hash (verbatim).
    from threatlens.detection_library.normalize import content_fingerprint

    rule = _BY_SOURCE["sigmahq"]
    assert rule.content is not None
    assert content_fingerprint(rule.content) == rule.version.content_hash
