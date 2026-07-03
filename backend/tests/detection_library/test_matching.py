"""Recommendation / matching tests (ranking, provenance, determinism)."""

from __future__ import annotations

from threatlens.detection_library import recommend
from threatlens.detection_library.types import RuleMatchType

from .corpus import LIBRARY, NOW, SCENARIOS

_BY_ID = {s.id: s.summary for s in SCENARIOS}


def _rec(scenario_id: str):
    return recommend(_BY_ID[scenario_id], LIBRARY)


def test_recommendation_is_deterministic() -> None:
    for s in SCENARIOS:
        assert recommend(s.summary, LIBRARY) == recommend(s.summary, LIBRARY)


def test_generated_at_is_inherited_not_clock() -> None:
    # Pure: the matcher never reads the clock; it inherits the summary timestamp.
    assert _rec("ip_c2").generated_at == NOW


def test_exact_matches_rank_before_partial_before_related() -> None:
    rec = _rec("multi_ioc")
    ranks = {RuleMatchType.EXACT: 0, RuleMatchType.PARTIAL: 1, RuleMatchType.RELATED: 2}
    order = [ranks[m.match_type] for m in rec.matches]
    assert order == sorted(order)
    assert rec.exact_count >= 1


def test_exact_match_shares_the_investigations_ioc() -> None:
    rec = _rec("ip_c2")
    exact = [m for m in rec.matches if m.match_type is RuleMatchType.EXACT]
    assert exact
    assert all(m.shared_iocs for m in exact)


def test_empty_investigation_yields_no_matches() -> None:
    rec = _rec("no_findings")
    assert rec.is_empty
    assert rec.matches == ()


def test_none_type_never_surfaces() -> None:
    for s in SCENARIOS:
        rec = recommend(s.summary, LIBRARY)
        assert all(m.match_type is not RuleMatchType.NONE for m in rec.matches)


def test_provenance_is_preserved_on_every_match() -> None:
    rec = _rec("ip_c2")
    for m in rec.matches:
        assert m.rule.source.repository  # repository
        assert m.rule.author.name  # author
        assert m.rule.license.spdx_id  # license
        assert m.rule.version.content_hash  # version
        assert m.rule.url  # original URL


def test_limit_caps_results() -> None:
    rec = recommend(_BY_ID["multi_ioc"], LIBRARY, limit=2)
    assert len(rec.matches) == 2


def test_ranking_is_stable_across_runs() -> None:
    a = [m.rule.id for m in _rec("multi_ioc").matches]
    b = [m.rule.id for m in _rec("multi_ioc").matches]
    assert a == b


def test_counts_match_the_matches() -> None:
    rec = _rec("ip_c2")
    assert rec.exact_count == sum(m.match_type is RuleMatchType.EXACT for m in rec.matches)
    assert rec.partial_count == sum(m.match_type is RuleMatchType.PARTIAL for m in rec.matches)
    assert rec.related_count == sum(m.match_type is RuleMatchType.RELATED for m in rec.matches)
