"""Availability contracts: derived records, backend parity and bounded queries."""

from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

from threatlens.threat_feed.bookmarks import BookmarkRequest, availability
from threatlens.threat_feed.models import FeedRegion, FeedTopic, FeedVulnerability, ThreatFeedItem
from threatlens.threat_feed.storage import FeedStorage


@pytest.fixture(params=["memory", "sqlite"])
def storage(request, monkeypatch, tmp_path):
    monkeypatch.setenv("THREATLENS_STORAGE_BACKEND", request.param)
    monkeypatch.setenv("THREATLENS_DATABASE_PATH", str(tmp_path / "bookmarks.db"))
    return FeedStorage()


def item():
    now = datetime.now(UTC)
    return ThreatFeedItem(
        id="zero-day",
        source_id="talos",
        source_name="Talos",
        source_kind="rss",
        title="Source reports a zero-day without an assigned CVE",
        excerpt="Source metadata",
        summary="Source metadata",
        url="https://example.test/report",
        published_at=now,
        collected_at=now,
        region=FeedRegion.GLOBAL,
        relevance="general",
        topic=FeedTopic.VULNERABILITY,
    )


def test_official_and_no_cve_availability(storage):
    news = item()
    now = datetime.now(UTC)
    storage.save_items([news])
    storage.save_vulnerabilities(
        [
            FeedVulnerability(
                id="CVE-2026-1234",
                cve_id="CVE-2026-1234",
                title="Official record",
                activity_at=now,
                updated_at=now,
            )
        ]
    )
    request = BookmarkRequest.model_validate(
        {
            "items": [
                {"kind": "vulnerability", "id": "report-zero-day"},
                {"kind": "vulnerability", "id": "CVE-2026-1234"},
                {"kind": "vulnerability", "id": "CVE-2026-9999"},
            ]
        }
    )
    result = availability(storage, request)
    assert [r.available for r in result] == [True, True, False]
    assert result[0].title == news.title and result[1].title == "Official record"


def test_postgres_uses_one_parameterized_combined_query(storage, monkeypatch):
    calls = []
    news = item()

    class DB:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def execute(self, query, parameters):
            calls.append((query, parameters))
            return SimpleNamespace(fetchall=lambda: [("news", news.model_dump(mode="json"))])

    monkeypatch.setattr(storage, "psycopg", SimpleNamespace(connect=lambda _, **kwargs: DB()))
    request = BookmarkRequest.model_validate(
        {
            "items": [
                {"kind": "news", "id": "zero-day"},
                {"kind": "vulnerability", "id": "report-zero-day"},
            ]
        }
    )
    assert all(r.available for r in availability(storage, request))
    assert len(calls) == 1 and "UNION ALL" in calls[0][0]
    assert "%s" in calls[0][0] and "report-zero-day" not in calls[0][0]
    assert set(calls[0][1]) == {"zero-day", "report-zero-day"}
