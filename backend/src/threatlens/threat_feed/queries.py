"""Bounded public feed reads: database filtering/counting, not collection hydration."""

from __future__ import annotations

import sqlite3
from contextlib import closing
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from .models import (
    FeedHomeResponse,
    FeedHomeSection,
    FeedListResponse,
    FeedRegion,
    FeedSummary,
    FeedTopic,
    FeedVulnerability,
    RegionCount,
    ThreatFeedItem,
    VulnerabilityListResponse,
)
from .sources import SOURCE_OPTIONS

if TYPE_CHECKING:
    from .storage import FeedStorage


def database_backed(storage: FeedStorage) -> bool:
    return storage.psycopg is not None or storage.backend == "sqlite"


def run(storage: FeedStorage, query: str, parameters: list[Any]) -> list[Any]:
    if storage.psycopg is not None:
        with storage.connect_postgres() as db:
            return list(db.execute(query.replace("?", "%s"), parameters).fetchall())
    with closing(sqlite3.connect(storage.path)) as db, db:
        return list(db.execute(query, parameters).fetchall())


def field(storage: FeedStorage, key: str, payload: str = "payload") -> str:
    return (
        f"{payload}->>'{key}'"
        if storage.psycopg is not None
        else f"json_extract({payload},'$.{key}')"
    )


def epoch(storage: FeedStorage, expression: str) -> str:
    return (
        f"EXTRACT(EPOCH FROM ({expression})::timestamptz)"
        if storage.psycopg is not None
        else f"(julianday({expression})-2440587.5)*86400.0"
    )


def array_has(storage: FeedStorage, key: str) -> str:
    if storage.psycopg is not None:
        return (
            f"EXISTS(SELECT 1 FROM jsonb_array_elements_text(payload->'{key}') "
            f"e(value) WHERE e.value=?)"
        )
    return f"EXISTS(SELECT 1 FROM json_each(payload,'$.{key}') e WHERE e.value=?)"


def contains(storage: FeedStorage, expression: str) -> str:
    function = "strpos" if storage.psycopg is not None else "instr"
    return f"{function}(LOWER({expression}),?)>0"


def news_where(
    storage: FeedStorage,
    region: FeedRegion | None,
    source: str | None,
    topic: FeedTopic | None,
    hours: int | None,
    query: str | None,
    now: datetime,
) -> tuple[str, list[Any]]:
    clauses: list[str] = []
    values: list[Any] = []
    for key, value in (("region", region), ("source_id", source), ("topic", topic)):
        if value:
            clauses.append(f"{field(storage, key)}=?")
            values.append(str(value))
    if hours:
        clauses.append("published_epoch>=?")
        values.append((now - timedelta(hours=hours)).timestamp())
    if query and query.strip():
        text = "||' '||".join(
            f"COALESCE({field(storage, key)},'')" for key in ("title", "summary", "source_name")
        )
        clauses.append(contains(storage, text))
        values.append(query.strip().lower())
    return " AND ".join(clauses) or "1=1", values


def news_page(
    storage: FeedStorage,
    *,
    region: FeedRegion | None = None,
    source: str | None = None,
    topic: FeedTopic | None = None,
    hours: int | None = None,
    query: str | None = None,
    page: int = 1,
    page_size: int = 20,
    sort: str = "newest",
) -> FeedListResponse:
    where, parameters = news_where(storage, region, source, topic, hours, query, datetime.now(UTC))
    order = "ASC" if sort == "oldest" else "DESC"
    rows = run(
        storage,
        f"WITH filtered AS (SELECT id,published_epoch,payload FROM "
        f"threat_feed_items WHERE {where}), "
        f"selected AS (SELECT payload FROM filtered ORDER BY "
        f"published_epoch {order},id {order} LIMIT ? OFFSET ?) "
        "SELECT 'item',CAST(payload AS text),0 FROM selected UNION ALL "
        "SELECT 'count','',COUNT(*) FROM filtered",
        parameters + [page_size, (page - 1) * page_size],
    )
    items = tuple(ThreatFeedItem.model_validate_json(row[1]) for row in rows if row[0] == "item")
    return FeedListResponse(
        items=items,
        total=next(int(r[2]) for r in rows if r[0] == "count"),
        page=page,
        page_size=page_size,
        source_options=SOURCE_OPTIONS,
    )


def home_page(
    storage: FeedStorage,
    *,
    query: str | None,
    topic: FeedTopic | None,
    hours: int | None,
    limit_per_region: int,
    sort: str,
    source: str | None = None,
) -> FeedHomeResponse:
    now = datetime.now(UTC)
    recent = (now - timedelta(hours=24)).timestamp()
    where, parameters = news_where(storage, None, source, topic, hours, query, now)
    order = "ASC" if sort == "oldest" else "DESC"
    region, severity = field(storage, "region"), field(storage, "severity")
    entity_count = (
        "COALESCE(jsonb_array_length(payload->'entities'),0)"
        if storage.psycopg is not None
        else "COALESCE(json_array_length(payload,'$.entities'),0)"
    )
    rows = run(
        storage,
        f"WITH filtered AS (SELECT id,published_epoch,payload,{region} AS "
        f"region FROM threat_feed_items WHERE {where}), "
        f"ranked AS (SELECT payload,ROW_NUMBER() OVER(PARTITION BY region "
        f"ORDER BY published_epoch {order},id {order}) AS n FROM filtered) "
        "SELECT 'item',CAST(payload AS text),0,0 FROM ranked WHERE n<=? UNION ALL "
        f"SELECT 'region',{region},COUNT(*),SUM(CASE WHEN "
        f"published_epoch>=? THEN 1 ELSE 0 END) FROM threat_feed_items GROUP BY {region} UNION ALL "
        "SELECT 'filtered',region,COUNT(*),0 FROM filtered GROUP BY region UNION ALL "
        f"SELECT 'critical','',COUNT(*),0 FROM threat_feed_items WHERE "
        f"{severity}='critical' UNION ALL "
        f"SELECT 'entities','',COALESCE(SUM({entity_count}),0),0 FROM "
        f"threat_feed_items WHERE published_epoch>=? UNION ALL "
        f"SELECT 'errors','',COUNT(*),0 FROM threat_feed_sources WHERE "
        f"{field(storage, 'last_error_code')} IS NOT NULL UNION ALL "
        "SELECT 'refresh',value,0,0 FROM threat_feed_state WHERE key='last_refresh'",
        parameters + [limit_per_region, recent, recent],
    )
    items = [ThreatFeedItem.model_validate_json(r[1]) for r in rows if r[0] == "item"]
    counts = {r[1]: (int(r[2]), int(r[3])) for r in rows if r[0] == "region"}
    filtered = {r[1]: int(r[2]) for r in rows if r[0] == "filtered"}
    refresh = next((datetime.fromisoformat(r[1]) for r in rows if r[0] == "refresh"), None)

    def value(name: str) -> int:
        return next((int(r[2]) for r in rows if r[0] == name), 0)

    return FeedHomeResponse(
        summary=FeedSummary(
            regions={
                r: RegionCount(total=counts.get(r, (0, 0))[0], recent=counts.get(r, (0, 0))[1])
                for r in FeedRegion
            },
            critical=value("critical"),
            new_iocs=value("entities"),
            source_errors=value("errors"),
            last_refreshed_at=refresh,
            next_refresh_at=refresh + timedelta(minutes=30) if refresh else None,
        ),
        sections={
            r: FeedHomeSection(
                items=tuple(
                    sorted(
                        (i for i in items if i.region == r),
                        key=lambda i: (i.published_at, i.id),
                        reverse=sort != "oldest",
                    )
                ),
                total=filtered.get(r, 0),
            )
            for r in FeedRegion
        },
        generated_at=now,
        source_options=SOURCE_OPTIONS,
    )


def vulnerability_page(
    storage: FeedStorage,
    *,
    query: str,
    category: str,
    severity: str,
    source: str,
    hours: int,
    page: int,
    page_size: int,
    sort: str,
) -> VulnerabilityListResponse:
    now = datetime.now(UTC)
    cutoff = (now - timedelta(hours=hours)).timestamp()
    recent = (now - timedelta(hours=24)).timestamp()
    clauses: list[str] = ["activity_epoch>=?"]
    parameters: list[Any] = [cutoff]
    if source:
        clauses.append(array_has(storage, "sources"))
        parameters.append(source)
    if severity:
        clauses.append(f"{field(storage, 'severity')}=?")
        parameters.append(severity)
    if query.strip():
        text = "||' '||".join(
            f"COALESCE({field(storage, k)},'')"
            for k in ("title", "cve_id", "description", "products")
        )
        clauses.append(contains(storage, text))
        parameters.append(query.strip().lower())
    if category == "new_cves":
        clauses.append(f"{epoch(storage, field(storage, 'published_at'))}>=?")
        parameters.append(cutoff)
    if category in {"zero_days", "known_exploited"}:
        key = "reported_zero_day" if category == "zero_days" else "known_exploited"
        clauses.append(f"{field(storage, key)}=?")
        parameters.append("true" if storage.psycopg is not None else 1)
    where = " AND ".join(clauses)
    order = "ASC" if sort == "oldest" else "DESC"
    report_array = (
        "jsonb_array_elements(payload->'reports')"
        if storage.psycopg is not None
        else "json_each(payload,'$.reports')"
    )
    report = "e.value"
    zero = field(storage, "zero_day", report)
    published = epoch(storage, field(storage, "published_at", report))
    truth = "'true'" if storage.psycopg is not None else "1"
    sources_query = (
        "SELECT DISTINCT e.value FROM base,jsonb_array_elements_text(payload->'sources') e(value)"
        if storage.psycopg is not None
        else "SELECT DISTINCT e.value FROM base,json_each(payload,'$.sources') e"
    )
    rows = run(
        storage,
        "WITH base AS (SELECT id,activity_epoch,payload FROM "
        "threat_feed_vulnerabilities WHERE activity_epoch>=?), "
        f"filtered AS (SELECT * FROM base WHERE {where}), selected AS "
        f"(SELECT payload FROM filtered ORDER BY activity_epoch {order},id "
        f"{order} LIMIT ? OFFSET ?) "
        "SELECT 'item',CAST(payload AS text),0 FROM selected UNION ALL "
        "SELECT 'count','',COUNT(*) FROM filtered UNION ALL "
        f"SELECT 'published','',COUNT(*) FROM base WHERE "
        f"{epoch(storage, field(storage, 'published_at'))}>=? UNION ALL "
        f"SELECT 'zero','',COUNT(*) FROM base WHERE EXISTS(SELECT 1 FROM "
        f"{report_array} e WHERE {zero}={truth} AND {published}>=?) UNION ALL "
        f"SELECT 'kev','',COUNT(*) FROM base WHERE "
        f"{epoch(storage, field(storage, 'kev_added_at'))}>=? UNION ALL "
        f"SELECT 'source',value,0 FROM ({sources_query}) s UNION ALL "
        "SELECT key,value,0 FROM threat_feed_state WHERE key IN ('nvd_last_success','nvd_status')",
        [(now - timedelta(days=30)).timestamp()]
        + parameters
        + [page_size, (page - 1) * page_size, recent, recent, recent],
    )

    def value(name: str) -> int:
        return next((int(r[2]) for r in rows if r[0] == name), 0)

    state = {r[0]: r[1] for r in rows if r[0].startswith("nvd_")}
    from .vulnerabilities import link_reports

    items = link_reports(
        [FeedVulnerability.model_validate_json(r[1]) for r in rows if r[0] == "item"], [], now
    )
    return VulnerabilityListResponse(
        items=tuple(items),
        total=value("count"),
        page=page,
        page_size=page_size,
        published_24h=value("published"),
        zero_days_24h=value("zero"),
        kev_added_24h=value("kev"),
        sources=tuple(sorted({str(r[1]) for r in rows if r[0] == "source"})),
        sync_status=state.get("nvd_status", "not_started"),
        last_synced_at=datetime.fromisoformat(state["nvd_last_success"])
        if state.get("nvd_last_success")
        else None,
        generated_at=now,
    )
