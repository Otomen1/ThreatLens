"""Bounded, passive activity brief from the existing source-metadata index."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING
from urllib.parse import quote

from pydantic import BaseModel

from .queries import database_backed, field, run
from .workflow import RecordKind, references

if TYPE_CHECKING:
    from .storage import FeedStorage

KINDS: tuple[RecordKind, ...] = ("news", "vulnerability", "ioc")
SAMPLE_LIMIT = 3


class ActivityItem(BaseModel):
    kind: RecordKind
    id: str
    title: str
    source: str
    activity_at: datetime
    href: str


class ActivityGroup(BaseModel):
    total: int = 0
    items: tuple[ActivityItem, ...] = ()


class FeedActivity(BaseModel):
    since: datetime | None
    window_start: datetime
    generated_at: datetime
    limited: bool = False
    groups: dict[RecordKind, ActivityGroup]


def _item(
    kind: RecordKind, record_id: str, title: str, source: str, when: datetime
) -> ActivityItem:
    prefix = {"news": "", "vulnerability": "vulnerabilities/", "ioc": "ioc-reports/"}[kind]
    return ActivityItem(
        kind=kind,
        id=record_id,
        title=title,
        source=source,
        activity_at=when,
        href=f"/threat-feed/{prefix}{quote(record_id, safe='')}",
    )


def activity(
    storage: FeedStorage, since: datetime | None, *, now: datetime | None = None
) -> FeedActivity:
    now = now or datetime.now(UTC)
    if since is not None and (since.tzinfo is None or since.utcoffset() is None):
        raise ValueError("Visit timestamps must include a timezone.")
    if since is not None and since > now:
        raise ValueError("Visit timestamps must not be in the future.")
    cutoff = now - timedelta(days=30)
    start = max(since, cutoff) if since else now
    groups = {kind: ActivityGroup() for kind in KINDS}
    if since is not None and database_backed(storage):
        from ..ioc_feed.storage import get_storage

        get_storage(storage)  # Existing one-time reference backfill, never collection.
        title, source = field(storage, "title"), field(storage, "source")
        rows = run(
            storage,
            "WITH matched AS (SELECT kind,id,activity_epoch,payload FROM "
            "threat_feed_read_references WHERE kind IN ('news','vulnerability','ioc') "
            "AND activity_epoch>? AND activity_epoch<=?), ranked AS (SELECT "
            f"kind,id,{title} AS title,{source} AS source,activity_epoch,"
            "COUNT(*) OVER(PARTITION BY kind) AS total,ROW_NUMBER() OVER("
            "PARTITION BY kind ORDER BY activity_epoch DESC,id DESC) AS n FROM matched) "
            "SELECT kind,id,title,source,activity_epoch,total FROM ranked WHERE n<=? "
            "ORDER BY kind,activity_epoch DESC,id DESC",
            [start.timestamp(), now.timestamp(), SAMPLE_LIMIT],
        )
        for kind in KINDS:
            selected = [row for row in rows if row[0] == kind]
            groups[kind] = ActivityGroup(
                total=int(selected[0][5]) if selected else 0,
                items=tuple(
                    _item(kind, r[1], r[2], r[3], datetime.fromtimestamp(r[4], UTC))
                    for r in selected
                ),
            )
    elif since is not None:
        records = references(storage)
        for kind in KINDS:
            matched = sorted(
                (r for r in records if r.kind == kind and start < r.activity_at <= now),
                key=lambda r: (r.activity_at, r.id),
                reverse=True,
            )
            groups[kind] = ActivityGroup(
                total=len(matched),
                items=tuple(
                    _item(r.kind, r.id, r.title, r.source, r.activity_at)
                    for r in matched[:SAMPLE_LIMIT]
                ),
            )
    return FeedActivity(
        since=since,
        window_start=start,
        generated_at=now,
        limited=since is not None and since < cutoff,
        groups=groups,
    )
