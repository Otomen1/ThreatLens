"""Compact stored reference index for exact search and related-intelligence reads."""

from __future__ import annotations

import json
import re
import sqlite3
from contextlib import closing
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any
from urllib.parse import quote

from ..ioc_feed.models import Indicator, IocReport
from ..ioc_feed.parsers import normalize
from .models import FeedVulnerability, ThreatFeedItem
from .queries import contains, run
from .workflow import (
    FeedReference,
    FeedRelated,
    FeedSearch,
    RelatedReference,
    SearchGroup,
    canonical_url,
    cve,
)

if TYPE_CHECKING:
    from .storage import FeedStorage


def news_reference(item: ThreatFeedItem) -> FeedReference:
    cves = {v for e in item.entities if (v := cve(e.normalized_value))} | {
        v.upper()
        for v in re.findall(r"\bCVE-\d{4}-\d{4,20}\b", f"{item.title} {item.excerpt}", re.I)
    }
    return FeedReference(
        kind="news",
        id=item.id,
        title=item.title,
        href=f"/threat-feed/{quote(item.id, safe='')}",
        activity_at=item.published_at,
        source=item.source_name,
        cves=tuple(sorted(cves))[:100],
        indicators=tuple(
            sorted({n.value for e in item.entities if (n := normalize(e.normalized_value))})
        ),
        urls=(canonical_url(str(item.url)),),
        text=" ".join(
            [item.title, item.excerpt, item.summary, item.vendor or "", item.product or ""]
        ),
    )


def vulnerability_reference(record: FeedVulnerability) -> FeedReference:
    return FeedReference(
        kind="vulnerability",
        id=record.id,
        title=record.title,
        href=f"/threat-feed/vulnerabilities/{quote(record.id, safe='')}",
        activity_at=record.activity_at,
        source=", ".join(record.sources),
        cves=(record.cve_id,) if record.cve_id else (),
        urls=tuple(canonical_url(str(r.url)) for r in record.reports),
        text=" ".join([record.title, record.description, *record.products]),
    )


def ioc_reference(report: IocReport, items: tuple[Indicator, ...]) -> FeedReference:
    return FeedReference(
        kind="ioc",
        id=report.id,
        title=report.title,
        href=f"/threat-feed/ioc-reports/{quote(report.id, safe='')}",
        activity_at=report.activity_at,
        source=report.vendor,
        cves=report.cves,
        indicators=tuple(i.value for i in items),
        urls=(canonical_url(report.article_url),) if report.article_url else (),
        text=" ".join([report.title, report.vendor]),
    )


def write(storage: FeedStorage, records: list[FeedReference], db: Any = None) -> None:
    if not records:
        return
    values = [
        (r.kind, r.id, r.activity_at.timestamp(), r.text.casefold(), r.model_dump_json())
        for r in records
    ]
    query = (
        "INSERT INTO threat_feed_read_references(kind,id,"
        "activity_epoch,search_text,payload) VALUES (?,?,?,?,?) "
        "ON CONFLICT(kind,id) DO UPDATE SET activity_epoch=excluded.activity_epoch,"
        "search_text=excluded.search_text,payload=excluded.payload"
    )
    if storage.psycopg is not None:
        query = query.replace("?", "%s").replace("%s) ON CONFLICT", "%s::jsonb) ON CONFLICT")
    if db is not None:
        if storage.psycopg is not None:
            with db.cursor() as cursor:
                cursor.executemany(query, values)
        else:
            db.executemany(query, values)
    elif storage.psycopg is not None:
        with storage.psycopg.connect(storage.url) as connection, connection.cursor() as cursor:
            cursor.executemany(query, values)
    else:
        with closing(sqlite3.connect(storage.path)) as connection, connection:
            connection.executemany(query, values)


def intersects(storage: FeedStorage, key: str) -> str:
    if storage.psycopg is not None:
        return (
            f"EXISTS(SELECT 1 FROM jsonb_array_elements_text(payload->'{key}') "
            f"a(value) JOIN jsonb_array_elements_text(?::jsonb) b(value) ON a.value=b.value)"
        )
    return (
        f"EXISTS(SELECT 1 FROM json_each(payload,'$.{key}') a JOIN "
        f"json_each(?) b ON a.value=b.value)"
    )


def search_index(
    storage: FeedStorage, query: str, pages: dict[str, int], oldest: bool
) -> FeedSearch:
    from ..ioc_feed.storage import get_storage

    get_storage(storage)  # Ensures the one-time IOC metadata backfill has completed.
    normalized = cve(query)
    observable = normalize(query)
    if normalized:
        where = intersects(storage, "cves")
        value = json.dumps([normalized])
    elif observable:
        where = intersects(storage, "indicators")
        value = json.dumps([observable.value])
    else:
        where = contains(storage, "search_text")
        value = query.casefold().strip()
    direction = "ASC" if oldest else "DESC"
    offsets = [(pages.get(kind, 1) - 1) * 20 for kind in ("news", "vulnerability", "ioc")]
    rows = run(
        storage,
        "WITH matched AS (SELECT kind,id,activity_epoch,payload FROM "
        "threat_feed_read_references WHERE activity_epoch>=? AND " + where + "), "
        f"ranked AS (SELECT kind,payload,ROW_NUMBER() OVER(PARTITION BY kind "
        f"ORDER BY activity_epoch {direction},id {direction}) AS n FROM matched), "
        "selected AS (SELECT kind,payload FROM ranked WHERE n>CASE kind WHEN "
        "'news' THEN ? WHEN 'vulnerability' THEN ? ELSE ? END AND n<=CASE kind "
        "WHEN 'news' THEN ? WHEN 'vulnerability' THEN ? ELSE ? END) "
        "SELECT kind,CAST(payload AS text),0 FROM selected UNION ALL SELECT "
        "kind,'',COUNT(*) FROM matched GROUP BY kind",
        [(datetime.now(UTC) - timedelta(days=30)).timestamp(), value]
        + offsets
        + [v + 20 for v in offsets],
    )
    groups = {}
    for kind in ("news", "vulnerability", "ioc"):
        selected = tuple(
            FeedReference.model_validate_json(r[1]).model_copy(
                update={"indicators": (), "text": "", "urls": ()}
            )
            for r in rows
            if r[0] == kind and r[1]
        )
        groups[kind] = SearchGroup(
            items=selected,
            total=next((int(r[2]) for r in rows if r[0] == kind and not r[1]), 0),
            page=pages.get(kind, 1),
        )
    return FeedSearch(groups=groups, generated_at=datetime.now(UTC), poc_cve=normalized)


def related_index(storage: FeedStorage, kind: str, record_id: str) -> FeedRelated | None:
    from ..ioc_feed.storage import get_storage

    get_storage(storage)
    cutoff = (datetime.now(UTC) - timedelta(days=30)).timestamp()
    source_rows = run(
        storage,
        "SELECT CAST(payload AS text) FROM threat_feed_read_references WHERE "
        "kind=? AND id=? AND activity_epoch>=?",
        [kind, record_id, cutoff],
    )
    if not source_rows:
        return None
    source = FeedReference.model_validate_json(source_rows[0][0])
    clauses = []
    args: list[Any] = [cutoff, kind, record_id]
    for key, values in (
        ("cves", source.cves),
        ("urls", tuple(v for v in source.urls if v)),
        ("indicators", source.indicators),
    ):
        if values:
            clauses.append(intersects(storage, key))
            args.append(json.dumps(values))
    if not clauses:
        return FeedRelated(items=(), cves=source.cves)
    rows = run(
        storage,
        "SELECT CAST(payload AS text) FROM threat_feed_read_references WHERE "
        "activity_epoch>=? AND NOT(kind=? AND id=?) AND ("
        + " OR ".join(clauses)
        + ") ORDER BY activity_epoch DESC,id DESC LIMIT 100",
        args,
    )
    result = []
    for row in rows:
        record = FeedReference.model_validate_json(row[0])
        shared = set(source.cves) & set(record.cves)
        reason = "References the same CVE"
        if not shared:
            shared = (set(source.urls) & set(record.urls)) - {""}
            reason = "Links to the same canonical article"
        if not shared:
            shared = set(source.indicators) & set(record.indicators)
            reason = "References the same indicator; shared campaign not established"
        if shared:
            result.append(
                RelatedReference(
                    record=record.model_copy(update={"indicators": (), "text": "", "urls": ()}),
                    reason=reason,
                    supporting_values=tuple(sorted(shared))[:20],
                )
            )
    return FeedRelated(items=tuple(result), cves=source.cves)
