from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from threatlens.api.routes.threat_feed import get_threat_feed_service, router
from threatlens.ioc_feed.models import IocReport
from threatlens.ioc_feed.storage import get_storage
from threatlens.threat_feed.activity import KINDS, activity
from threatlens.threat_feed.models import (
    FeedRegion,
    FeedTopic,
    FeedVulnerability,
    ThreatFeedItem,
)
from threatlens.threat_feed.service import ThreatFeedService
from threatlens.threat_feed.storage import FeedStorage


@pytest.fixture(params=["memory", "sqlite"])
def populated(request, monkeypatch, tmp_path):
    monkeypatch.setenv("THREATLENS_STORAGE_BACKEND", request.param)
    monkeypatch.setenv("THREATLENS_DATABASE_PATH", str(tmp_path / "brief.db"))
    monkeypatch.delenv("VERCEL", raising=False)
    storage = FeedStorage()
    now = datetime.now(UTC)
    iocs = get_storage(storage)
    for i in range(8):
        when = now - timedelta(hours=1, minutes=i)
        storage.save_items(
            [
                ThreatFeedItem(
                    id=f"news-{i}",
                    title=f"News {i}",
                    source_id="talos",
                    source_name="Cisco Talos",
                    source_kind="rss",
                    summary="Stored metadata",
                    url=f"https://example.test/{i}",
                    published_at=when,
                    collected_at=now,
                    region=FeedRegion.GLOBAL,
                    relevance="general",
                    topic=FeedTopic.RESEARCH,
                )
            ]
        )
        storage.save_vulnerabilities(
            [
                FeedVulnerability(
                    id=f"CVE-2026-123{i}",
                    title=f"Vulnerability {i}",
                    activity_at=when,
                    updated_at=when,
                    sources=("NVD",),
                )
            ]
        )
        iocs.save(
            IocReport(
                id=f"ioc-{i}",
                title=f"IOC {i}",
                vendor="talos",
                path=f"{i}.txt",
                source_url=f"https://example.test/{i}",
                activity_at=when,
                collected_at=now,
                commit="a" * 40,
                blob="b" * 40,
                license="CC0-1.0",
                license_url="https://example.test/license",
                attribution="Cisco Talos",
            ),
            (),
            {},
        )
    return storage, now


def test_activity_counts_all_records_but_samples_are_bounded(populated):
    storage, now = populated
    result = activity(storage, now - timedelta(hours=2), now=now)
    assert set(result.groups) == set(KINDS)
    for kind in KINDS:
        assert result.groups[kind].total == 8
        assert len(result.groups[kind].items) == 3
        assert [r.title for r in result.groups[kind].items] == [
            f"{ {'news': 'News', 'vulnerability': 'Vulnerability', 'ioc': 'IOC'}[kind] } {i}"
            for i in range(3)
        ]
        assert all(
            r.kind == kind and r.href.startswith("/threat-feed/") for r in result.groups[kind].items
        )
    assert not result.limited
    # Source dates, not today's collection time, determine the interval.
    assert all(
        g.total == 0
        for g in activity(storage, now - timedelta(minutes=30), now=now).groups.values()
    )


def test_first_visit_boundaries_retention_and_invalid_times(populated):
    storage, now = populated
    first = activity(storage, None, now=now)
    assert first.since is None and first.window_start == now
    assert all(group.total == 0 for group in first.groups.values())
    limited = activity(storage, now - timedelta(days=90), now=now)
    assert limited.limited and limited.window_start == now - timedelta(days=30)
    exact = activity(storage, now - timedelta(hours=1), now=now)
    assert all(group.total == 0 for group in exact.groups.values())
    with pytest.raises(ValueError):
        activity(storage, now.replace(tzinfo=None), now=now)
    with pytest.raises(ValueError):
        activity(storage, now + timedelta(seconds=1), now=now)
    assert all(
        group.total == 0
        for group in activity(
            storage, now - timedelta(days=1), now=now - timedelta(hours=2)
        ).groups.values()
    )


def test_database_brief_is_one_bounded_select_with_no_full_payload_hydration(
    populated, monkeypatch
):
    storage, now = populated
    if storage.backend != "sqlite":
        return
    import sqlite3

    connect = sqlite3.connect
    statements = []

    def tracked(*args, **kwargs):
        db = connect(*args, **kwargs)
        db.set_trace_callback(statements.append)
        return db

    monkeypatch.setattr(sqlite3, "connect", tracked)
    monkeypatch.setattr(storage, "list_items", lambda: pytest.fail("Full news read"))
    monkeypatch.setattr(
        storage, "list_vulnerabilities", lambda: pytest.fail("Full vulnerability read")
    )
    monkeypatch.setattr(get_storage(storage), "snapshot", lambda **_: pytest.fail("Full IOC read"))
    with patch.object(
        ThreatFeedItem, "model_validate_json", side_effect=AssertionError("Hydration")
    ):
        result = activity(storage, now - timedelta(hours=2), now=now)
    assert result.groups["news"].total == 8
    assert len(statements) == 1 and statements[0].startswith("WITH matched")


def test_public_activity_api_is_passive_bounded_and_validates_cutoff(populated, monkeypatch):
    storage, now = populated
    monkeypatch.setattr(
        "threatlens.threat_feed.service.fetch_source", lambda _: pytest.fail("External request")
    )
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_threat_feed_service] = lambda: ThreatFeedService(storage)
    with TestClient(app) as client:
        response = client.get(
            "/api/v1/threat-feed/activity", params={"since": (now - timedelta(hours=2)).isoformat()}
        )
        assert response.status_code == 200
        assert response.headers["cache-control"].startswith("public, s-maxage=300")
        assert set(response.json()["groups"]["news"]["items"][0]) == {
            "kind",
            "id",
            "title",
            "source",
            "activity_at",
            "href",
        }
        first = client.get("/api/v1/threat-feed/activity")
        assert first.status_code == 200 and first.headers["cache-control"] == "no-store"
        assert first.json()["since"] is None
        for invalid in ("bad", "2026-01-01T00:00:00", (now + timedelta(days=1)).isoformat()):
            assert (
                client.get("/api/v1/threat-feed/activity", params={"since": invalid}).status_code
                == 422
            )
