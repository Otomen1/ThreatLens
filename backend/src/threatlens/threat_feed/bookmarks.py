"""Bounded, stored-metadata-only availability checks for browser bookmarks."""

import json
import re
import sqlite3
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field

from ..ioc_feed.storage import get_storage
from .models import FeedVulnerability, ThreatFeedItem
from .storage import FeedStorage
from .vulnerabilities import link_reports
from .workflow import RecordKind


class BookmarkKey(BaseModel):
    kind: RecordKind
    id: str = Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9_.:-]+$")


class BookmarkRequest(BaseModel):
    items: tuple[BookmarkKey, ...] = Field(min_length=1, max_length=20)


class BookmarkAvailability(BookmarkKey):
    available: bool
    title: str | None = None


def availability(
    storage: FeedStorage, request: BookmarkRequest
) -> tuple[BookmarkAvailability, ...]:
    keys = {(item.kind, item.id) for item in request.items}
    ids = {
        kind: [value for k, value in keys if k == kind] for kind in ("news", "vulnerability", "ioc")
    }
    iocs = get_storage(storage) if ids["ioc"] else None
    rows: list[tuple[str, Any]] = []
    if storage.psycopg is not None or storage.backend == "sqlite":
        placeholder = "%s" if storage.psycopg is not None else "?"
        parts: list[str] = []
        parameters: list[str] = []
        for kind, table in (
            ("news", "threat_feed_items"),
            ("vulnerability", "threat_feed_vulnerabilities"),
            ("ioc", "threat_feed_ioc_reports"),
        ):
            values = ids[kind]
            # News may synthesize vulnerability records, including reports without a CVE.
            if kind == "news" and ids["vulnerability"]:
                news_ids = values + [
                    value.removeprefix("report-")
                    for value in ids["vulnerability"]
                    if value.startswith("report-")
                ]
                cves = [
                    value
                    for value in ids["vulnerability"]
                    if re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,20}", value)
                ]
                conditions = []
                if news_ids:
                    markers = ",".join(placeholder for _ in news_ids)
                    conditions.append(f"id IN ({markers})")
                    parameters.extend(news_ids)
                for value in cves:
                    conditions.append(f"LOWER(CAST(payload AS text)) LIKE {placeholder}")
                    parameters.append(f"%{value.lower()}%")
                if conditions:
                    parts.append(
                        f"SELECT '{kind}',payload FROM {table} WHERE " + " OR ".join(conditions)
                    )
            elif values:
                markers = ",".join(placeholder for _ in values)
                parts.append(f"SELECT '{kind}',payload FROM {table} WHERE id IN ({markers})")
                parameters.extend(values)
        query = " UNION ALL ".join(parts)
        if storage.psycopg is not None:
            with storage.psycopg.connect(storage.url) as db:
                rows = db.execute(query, parameters).fetchall()
        else:
            with sqlite3.connect(storage.path) as db:
                rows = db.execute(query, parameters).fetchall()
    else:
        rows.extend(("news", item.model_dump()) for item in storage.memory_items.values())
        rows.extend(
            ("vulnerability", item.model_dump()) for item in storage.memory_vulnerabilities.values()
        )
        if iocs is not None:
            rows.extend(("ioc", item.model_dump()) for item in iocs.reports.values())
    decoded = [
        (kind, json.loads(payload) if isinstance(payload, str) else payload)
        for kind, payload in rows
    ]
    news = [ThreatFeedItem.model_validate(payload) for kind, payload in decoded if kind == "news"]
    titles = {("news", item.id): item.title for item in news}
    titles.update(
        {("ioc", payload["id"]): payload["title"] for kind, payload in decoded if kind == "ioc"}
    )
    if ids["vulnerability"]:
        records = link_reports(
            [
                FeedVulnerability.model_validate(payload)
                for kind, payload in decoded
                if kind == "vulnerability"
            ],
            news,
            datetime.now(UTC),
        )
        titles.update({("vulnerability", item.id): item.title for item in records})
    return tuple(
        BookmarkAvailability(
            **item.model_dump(),
            available=(item.kind, item.id) in titles,
            title=titles.get((item.kind, item.id)),
        )
        for item in request.items
    )
