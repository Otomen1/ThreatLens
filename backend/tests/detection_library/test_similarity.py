"""Deterministic similarity + classification tests (no AI, no embeddings)."""

from __future__ import annotations

from threatlens.detection_library import profile_from_summary, score
from threatlens.detection_library.similarity import (
    _W_ACTOR,
    _W_CATEGORY,
    _W_IOC,
    _W_MALWARE,
    _W_MITRE,
    _W_PLATFORM,
    _W_TAGS,
)
from threatlens.detection_library.types import RuleMatchType
from threatlens.entities.types import EntityType

from .corpus import IP, LIBRARY, SCENARIOS

_BY_ID = {s.id: s.summary for s in SCENARIOS}


def _rule(rule_id: str):
    return next(r for r in LIBRARY.rules if r.rule_id == rule_id)


def test_weights_sum_to_100() -> None:
    total = _W_IOC + _W_MITRE + _W_MALWARE + _W_ACTOR + _W_CATEGORY + _W_TAGS + _W_PLATFORM
    assert total == 100


def test_exact_when_ioc_shared() -> None:
    profile = profile_from_summary(_BY_ID["ip_c2"])
    result = score(profile, _rule("2400001"))  # ET rule targeting the same IP
    assert result.match_type is RuleMatchType.EXACT
    assert f"ipv4:{IP}" in result.shared_iocs
    assert result.similarity > 0


def test_partial_when_only_technique_shared() -> None:
    profile = profile_from_summary(_BY_ID["powershell"])
    result = score(profile, _rule("ms-sentinel-encoded-powershell"))  # shares T1059.001, no IOC
    assert result.match_type is RuleMatchType.PARTIAL
    assert result.shared_iocs == ()
    assert "T1059.001" in result.shared_techniques


def test_none_when_no_overlap_at_all() -> None:
    profile = profile_from_summary(_BY_ID["powershell"])
    # A network SSH-scan rule shares no technique/ioc/malware/actor with a PS host finding.
    result = score(profile, _rule("2400003"))
    assert result.match_type in (RuleMatchType.RELATED, RuleMatchType.NONE)


def test_score_is_deterministic_and_bounded() -> None:
    profile = profile_from_summary(_BY_ID["ip_c2"])
    for rule in LIBRARY.rules:
        a, b = score(profile, rule), score(profile, rule)
        assert a == b
        assert 0 <= a.similarity <= 100
        assert 0 <= a.coverage <= 100


def test_coverage_reflects_primary_signal_overlap() -> None:
    profile = profile_from_summary(_BY_ID["ip_c2"])  # 1 IOC + 1 technique = 2 primary signals
    result = score(profile, _rule("2400001"))  # covers the IP + T1071 → 100%
    assert result.coverage == 100


def test_actor_overlap_drives_partial() -> None:
    profile = profile_from_summary(_BY_ID["actor_only"])
    result = score(profile, _rule("APT_Sample_Payload_Hash"))  # tagged actor APT29
    assert result.match_type is RuleMatchType.PARTIAL
    assert "apt29" in result.shared_actors


def test_profile_extraction_is_deterministic() -> None:
    s = _BY_ID["multi_ioc"]
    p = profile_from_summary(s)
    assert p == profile_from_summary(s)
    assert (EntityType.IPV4, IP) in p.iocs
    assert "T1071" in p.techniques
