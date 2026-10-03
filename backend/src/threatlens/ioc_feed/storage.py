"""Transactional report replacement and indexed relational provenance."""

import json
import os
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from threading import Lock
from typing import Any
from weakref import WeakKeyDictionary

from ..threat_feed.storage import FeedStorage
from .history import MAX_HISTORY_BYTES, MAX_REVISIONS, IocRevision, maintain, revision
from .models import Indicator, IocReport

_stores: WeakKeyDictionary[FeedStorage, "IocStorage"] = WeakKeyDictionary()
_stores_lock = Lock()
MAX_REPORTS = 500
MAX_UNIQUE_INDICATORS = 50_000
MAX_ASSOCIATIONS = 100_000


class StorageCapacity(ValueError):
    """Free-tier protection: retain existing data and pending work."""


def get_storage(feed: FeedStorage) -> "IocStorage":
    with _stores_lock:
        if feed not in _stores:
            _stores[feed] = IocStorage(feed)
        return _stores[feed]


class IocStorage:
    def __init__(self, feed: FeedStorage) -> None:
        self.feed = feed
        self.pg = feed.psycopg is not None
        self.memory = not self.pg and feed.backend != "sqlite"
        self.reports: dict[str, IocReport] = {}
        self.indicators: dict[str, tuple[Indicator, ...]] = {}
        self.history: dict[str, IocRevision] = {}
        if (feed.backend == "postgres" or os.getenv("VERCEL")) and not self.pg:
            raise ValueError("Durable IOC database is unavailable")
        if not self.memory:
            with self.connection() as db:
                for statement in schema(self.pg):
                    db.execute(statement)

    @contextmanager
    def connection(self) -> Iterator[Any]:
        if self.pg:
            assert self.feed.psycopg is not None
            with self.feed.psycopg.connect(self.feed.url) as db:
                yield db
        else:
            with sqlite3.connect(self.feed.path) as db:
                db.execute("PRAGMA foreign_keys=ON")
                yield db

    def sql(self, statement: str) -> str:
        return statement.replace("?", "%s") if self.pg else statement

    def decode(self, payload: Any) -> Any:
        return payload if isinstance(payload, dict) else json.loads(payload)

    def save(
        self, report: IocReport, indicators: tuple[Indicator, ...], state: dict[str, str]
    ) -> None:
        report = report.model_copy(
            update={
                "indicator_count": len(indicators),
                "types": tuple(sorted({i.type for i in indicators})),
            }
        )
        if self.memory:
            with self.feed._lease_lock:
                ids = {i.id for items in self.indicators.values() for i in items}
                edges = sum(len(items) for items in self.indicators.values())
                old_edges = len(self.indicators.get(report.id, ()))
                if (
                    len(self.reports) + (report.id not in self.reports) > MAX_REPORTS
                    or len(ids | {i.id for i in indicators}) > MAX_UNIQUE_INDICATORS
                    or edges - old_edges + len(indicators) > MAX_ASSOCIATIONS
                ):
                    raise StorageCapacity
                old_report = self.reports.get(report.id)
                entry = revision(
                    report,
                    indicators,
                    (old_report, self.indicators[report.id]) if old_report else None,
                )
                if entry:
                    self.history[entry.id] = entry
                counts: dict[str, int] = {}
                size = 0
                for history_item in sorted(
                    self.history.values(), key=lambda r: (r.observed_at, r.id), reverse=True
                ):
                    counts[history_item.report_id] = counts.get(history_item.report_id, 0) + 1
                    length = len(history_item.model_dump_json().encode())
                    if (
                        history_item.observed_at < report.collected_at - timedelta(days=30)
                        or counts[history_item.report_id] > MAX_REVISIONS
                        or size + length > MAX_HISTORY_BYTES
                    ):
                        self.history.pop(history_item.id)
                        self.feed.memory_state[f"ioc_history_limited:{history_item.report_id}"] = (
                            "true"
                        )
                    else:
                        size += length
                self.reports[report.id] = report
                self.indicators[report.id] = indicators
                self.feed.memory_state.update(state)
            return
        with self.connection() as db:
            old_row = db.execute(
                self.sql("SELECT payload FROM threat_feed_ioc_reports WHERE id=?"), (report.id,)
            ).fetchone()
            old_items = (
                db.execute(
                    self.sql(
                        "SELECT i.payload,e.original FROM threat_feed_indicators i JOIN "
                        "threat_feed_report_indicators e ON e.indicator_id=i.id WHERE e.report_id=?"
                    ),
                    (report.id,),
                ).fetchall()
                if old_row
                else []
            )
            old = (
                (
                    IocReport.model_validate(self.decode(old_row[0])),
                    tuple(
                        Indicator.model_validate(self.decode(p)).model_copy(
                            update={"original": original}
                        )
                        for p, original in old_items
                    ),
                )
                if old_row
                else None
            )
            entry = revision(report, indicators, old)
            count = db.execute("SELECT COUNT(*) FROM threat_feed_ioc_reports").fetchone()[0]
            exists = db.execute(
                self.sql("SELECT 1 FROM threat_feed_ioc_reports WHERE id=?"), (report.id,)
            ).fetchone()
            unique = db.execute("SELECT COUNT(*) FROM threat_feed_indicators").fetchone()[0]
            edges = db.execute("SELECT COUNT(*) FROM threat_feed_report_indicators").fetchone()[0]
            old_edges = db.execute(
                self.sql("SELECT COUNT(*) FROM threat_feed_report_indicators WHERE report_id=?"),
                (report.id,),
            ).fetchone()[0]
            existing_ids: set[str] = set()
            if indicators:
                placeholders = ",".join("?" for _ in indicators)
                existing_ids = {
                    row[0]
                    for row in db.execute(
                        self.sql(
                            f"SELECT id FROM threat_feed_indicators WHERE id IN ({placeholders})"
                        ),
                        tuple(i.id for i in indicators),
                    ).fetchall()
                }
            if (
                count + (exists is None) > MAX_REPORTS
                or unique + len({i.id for i in indicators} - existing_ids) > MAX_UNIQUE_INDICATORS
                or edges - old_edges + len(indicators) > MAX_ASSOCIATIONS
            ):
                raise StorageCapacity
            payload_cast = "::jsonb" if self.pg else ""
            db.execute(
                self.sql(
                    f"INSERT INTO threat_feed_ioc_reports VALUES (?,?,?,?,?{payload_cast}) "
                    "ON CONFLICT(id) DO UPDATE SET vendor=excluded.vendor,title=excluded.title,"
                    "activity_at=excluded.activity_at,payload=excluded.payload"
                ),
                (
                    report.id,
                    report.vendor,
                    report.title,
                    report.activity_at.isoformat(),
                    report.model_dump_json(),
                ),
            )
            db.execute(
                self.sql("DELETE FROM threat_feed_report_indicators WHERE report_id=?"),
                (report.id,),
            )
            for item in indicators:
                db.execute(
                    self.sql(
                        f"INSERT INTO threat_feed_indicators VALUES (?,?,?,?{payload_cast}) "
                        "ON CONFLICT(id) DO NOTHING"
                    ),
                    (item.id, item.type, item.value, item.model_dump_json()),
                )
                db.execute(
                    self.sql("INSERT INTO threat_feed_report_indicators VALUES (?,?,?)"),
                    (report.id, item.id, item.original),
                )
            for key, value in state.items():
                db.execute(
                    self.sql(
                        "INSERT INTO threat_feed_state VALUES (?,?) ON CONFLICT(key) "
                        "DO UPDATE SET value=excluded.value"
                    ),
                    (key, value),
                )
            maintain(db, self.sql, entry, self.pg, report.collected_at - timedelta(days=30))

    def changes(self, report_id: str, page: int = 1) -> dict[str, Any]:
        cutoff = datetime.now(UTC) - timedelta(days=30)
        if self.memory:
            items = [
                r
                for r in self.history.values()
                if r.report_id == report_id and r.observed_at >= cutoff
            ]
        else:
            with self.connection() as db:
                rows = db.execute(
                    self.sql(
                        "SELECT payload FROM threat_feed_ioc_revisions "
                        "WHERE report_id=? AND observed_at>=? "
                        "ORDER BY observed_at DESC,id DESC"
                    ),
                    (report_id, cutoff.isoformat()),
                ).fetchall()
            items = [IocRevision.model_validate(self.decode(r[0])) for r in rows]
        items.sort(key=lambda r: (r.observed_at, r.id), reverse=True)
        return {
            "items": items[(page - 1) * 5 : page * 5],
            "total": len(items),
            "page": page,
            "page_size": 5,
            "limited": self.feed.state(f"ioc_history_limited:{report_id}") == "true",
            "baseline": "Changes observed by ThreatLens only; no vendor archive implied.",
        }

    def detail(self, report_id: str) -> tuple[IocReport, tuple[Indicator, ...]] | None:
        if self.memory:
            report = self.reports.get(report_id)
            return (report, self.indicators[report_id]) if report else None
        with self.connection() as db:
            row = db.execute(
                self.sql("SELECT payload FROM threat_feed_ioc_reports WHERE id=?"), (report_id,)
            ).fetchone()
            if not row:
                return None
            rows = db.execute(
                self.sql(
                    "SELECT i.payload,e.original FROM threat_feed_indicators i "
                    "JOIN threat_feed_report_indicators e ON e.indicator_id=i.id "
                    "WHERE e.report_id=? ORDER BY i.type,i.value"
                ),
                (report_id,),
            ).fetchall()
        return IocReport.model_validate(self.decode(row[0])), tuple(
            Indicator.model_validate(self.decode(payload)).model_copy(update={"original": original})
            for payload, original in rows
        )

    def snapshot(
        self, *, query: str, vendor: str, kind: str, cutoff: datetime
    ) -> list[tuple[IocReport, tuple[Indicator, ...]]]:
        """Read only matching reports/edges, not the historical catalogue."""
        if self.memory:
            data = [(r, self.indicators[r.id]) for r in self.reports.values()]
        else:
            clauses = ["r.activity_at>=?"]
            args: list[Any] = [cutoff.isoformat()]
            if vendor:
                clauses.append("r.vendor=?")
                args.append(vendor)
            if kind:
                clauses.append(
                    "EXISTS(SELECT 1 FROM threat_feed_report_indicators e "
                    "JOIN threat_feed_indicators i ON i.id=e.indicator_id "
                    "WHERE e.report_id=r.id AND i.type=?)"
                )
                args.append(kind)
            if query:
                clauses.append(
                    "(LOWER(r.title) LIKE ? ESCAPE '\\' OR EXISTS(SELECT 1 "
                    "FROM threat_feed_report_indicators e JOIN threat_feed_indicators i "
                    "ON i.id=e.indicator_id WHERE e.report_id=r.id AND i.value=?))"
                )
                escaped = (
                    query.lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
                )
                args.extend([f"%{escaped}%", query])
            where = " AND ".join(clauses)
            # One round trip, but do not repeat each report's JSON for every indicator.
            with self.connection() as db:
                rows = db.execute(
                    self.sql(
                        "SELECT 'report',r.id,r.payload,NULL FROM threat_feed_ioc_reports r WHERE "
                        + where
                        + " UNION ALL SELECT 'indicator',r.id,i.payload,e.original "
                        "FROM threat_feed_ioc_reports r "
                        "JOIN threat_feed_report_indicators e ON e.report_id=r.id "
                        "JOIN threat_feed_indicators i ON i.id=e.indicator_id WHERE " + where
                    ),
                    args + args,
                ).fetchall()
            reports: dict[str, IocReport] = {}
            associated: dict[str, list[Indicator]] = {}
            for record_type, report_id, raw_payload, original in rows:
                if record_type == "report":
                    reports[report_id] = IocReport.model_validate(self.decode(raw_payload))
                else:
                    associated.setdefault(report_id, []).append(
                        Indicator.model_validate(self.decode(raw_payload)).model_copy(
                            update={"original": original}
                        )
                    )
            data = [(r, tuple(associated.get(r.id, []))) for r in reports.values()]
        return sorted(
            [
                (r, items)
                for r, items in data
                if r.activity_at >= cutoff
                and (not vendor or r.vendor == vendor)
                and (not kind or any(i.type == kind for i in items))
                and (
                    not query
                    or query.lower() in r.title.lower()
                    or any(query == i.value for i in items)
                )
            ],
            key=lambda pair: (pair[0].activity_at, pair[0].id),
            reverse=True,
        )

    def prune(self, cutoff: datetime) -> None:
        if self.memory:
            for revision_id, entry in list(self.history.items()):
                if entry.observed_at < cutoff:
                    self.history.pop(revision_id)
                    self.feed.memory_state[f"ioc_history_limited:{entry.report_id}"] = "true"
            for key in list(self.reports):
                if self.reports[key].activity_at < cutoff:
                    self.reports.pop(key)
                    self.indicators.pop(key, None)
            return
        with self.connection() as db:
            maintain(db, self.sql, None, self.pg, cutoff)
            db.execute(
                self.sql("DELETE FROM threat_feed_ioc_reports WHERE activity_at<?"),
                (cutoff.isoformat(),),
            )
            db.execute(
                "DELETE FROM threat_feed_indicators WHERE NOT EXISTS(SELECT 1 "
                "FROM threat_feed_report_indicators e "
                "WHERE e.indicator_id=threat_feed_indicators.id)"
            )


def schema(postgres: bool) -> list[str]:
    payload = "jsonb" if postgres else "text"
    statements = [
        "CREATE TABLE IF NOT EXISTS threat_feed_ioc_reports(id text PRIMARY KEY,"
        "vendor text NOT NULL,title text NOT NULL,activity_at text NOT NULL,"
        f"payload {payload} NOT NULL)",
        "CREATE TABLE IF NOT EXISTS threat_feed_indicators(id text PRIMARY KEY,"
        f"type text NOT NULL,value text NOT NULL,payload {payload} NOT NULL,UNIQUE(type,value))",
        "CREATE TABLE IF NOT EXISTS threat_feed_report_indicators(report_id text NOT NULL "
        "REFERENCES threat_feed_ioc_reports(id) ON DELETE CASCADE,indicator_id text NOT NULL "
        "REFERENCES threat_feed_indicators(id),original text NOT NULL,"
        "PRIMARY KEY(report_id,indicator_id))",
        "CREATE INDEX IF NOT EXISTS ioc_reports_vendor_activity_idx "
        "ON threat_feed_ioc_reports(vendor,activity_at DESC)",
        "CREATE INDEX IF NOT EXISTS ioc_reports_activity_idx "
        "ON threat_feed_ioc_reports(activity_at DESC)",
        "CREATE INDEX IF NOT EXISTS ioc_indicator_value_idx ON threat_feed_indicators(value)",
        "CREATE INDEX IF NOT EXISTS ioc_indicator_type_idx ON threat_feed_indicators(type)",
        "CREATE INDEX IF NOT EXISTS ioc_edges_indicator_idx "
        "ON threat_feed_report_indicators(indicator_id)",
        "CREATE TABLE IF NOT EXISTS threat_feed_ioc_revisions(id text PRIMARY KEY,"
        "report_id text NOT NULL REFERENCES threat_feed_ioc_reports(id) ON DELETE CASCADE,"
        "observed_at text NOT NULL,bytes integer NOT NULL,"
        f"payload {payload} NOT NULL)",
        "CREATE INDEX IF NOT EXISTS ioc_revisions_report_idx "
        "ON threat_feed_ioc_revisions(report_id,observed_at DESC)",
    ]
    if postgres:
        statements.extend(
            f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY"
            for table in (
                "threat_feed_ioc_reports",
                "threat_feed_indicators",
                "threat_feed_report_indicators",
                "threat_feed_ioc_revisions",
            )
        )
    return statements
