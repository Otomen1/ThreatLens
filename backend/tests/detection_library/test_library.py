"""Library index + search tests (every axis, deterministic order)."""

from __future__ import annotations

from threatlens.detection_library import DetectionLibrary
from threatlens.detection_library.types import (
    DetectionLanguage,
    DetectionSeverity,
    RulePlatform,
    SyncStatus,
)

from .corpus import DOMAIN, IP, LIBRARY


def test_library_holds_the_seed_corpus() -> None:
    assert len(LIBRARY) == 18
    assert LIBRARY.sync_status is SyncStatus.SEED


def test_search_by_ioc() -> None:
    res = LIBRARY.search(ioc=IP)
    assert res.total == 2
    assert {r.source.id for r in res.rules} == {"emerging-threats", "splunk"}


def test_search_by_technique_matches_subtechniques() -> None:
    assert LIBRARY.search(technique="T1071").total == 7  # includes T1071.001
    assert LIBRARY.search(technique="T1071.001").total == 2


def test_search_by_language_repository_platform() -> None:
    assert LIBRARY.search(language=DetectionLanguage.YARA).total == 3
    assert LIBRARY.search(repository="microsoft").total == 2
    assert LIBRARY.search(platform=RulePlatform.NETWORK).total == 5


def test_search_by_name_text_and_min_severity() -> None:
    assert LIBRARY.search(name="beacon").total >= 1
    assert LIBRARY.search(text="powershell").total == 4
    assert all(
        r.severity >= DetectionSeverity.HIGH
        for r in LIBRARY.search(min_severity=DetectionSeverity.HIGH).rules
    )


def test_search_by_domain_and_rule_id() -> None:
    assert LIBRARY.search(ioc=DOMAIN).total == 2
    assert LIBRARY.search(rule_id="2400001").total == 1


def test_filters_are_anded() -> None:
    res = LIBRARY.search(technique="T1071", language=DetectionLanguage.SPLUNK_SPL)
    assert res.total == 1
    assert res.rules[0].source.id == "splunk"


def test_search_pagination_is_stable() -> None:
    first = LIBRARY.search(limit=5, offset=0).rules
    second = LIBRARY.search(limit=5, offset=5).rules
    assert len(first) == 5
    assert not {r.id for r in first} & {r.id for r in second}  # no overlap
    # Deterministic: same query, same order.
    assert [r.id for r in LIBRARY.search(limit=5).rules] == [r.id for r in first]


def test_stats_counts_languages_and_sources() -> None:
    stats = LIBRARY.stats()
    assert stats.total_rules == 18
    assert stats.sources == 7
    assert stats.by_language["sigma"] == 4


def test_construction_deduplicates_by_id() -> None:
    dup = DetectionLibrary(LIBRARY.rules + LIBRARY.rules)
    assert len(dup) == len(LIBRARY)


def test_empty_search_returns_all() -> None:
    assert LIBRARY.search().total == 18
