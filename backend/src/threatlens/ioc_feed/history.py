"""Bounded observed revisions, never invented vendor history."""

import json
from datetime import datetime
from typing import Any

from pydantic import BaseModel

from .models import Indicator, IocReport
from .parsers import identity

MAX_HISTORY_BYTES = 20 * 1024 * 1024
MAX_REVISIONS = 10


class IocRevision(BaseModel):
    id: str
    report_id: str
    observed_at: datetime
    commit: str
    parser_version: str
    changed_fields: tuple[str, ...]
    added: tuple[Indicator, ...]
    removed: tuple[Indicator, ...]
    attribution: str
    license: str
    license_url: str


def revision(
    report: IocReport,
    items: tuple[Indicator, ...],
    old: tuple[IocReport, tuple[Indicator, ...]] | None,
) -> IocRevision | None:
    if old is None:
        return None
    fields = (
        "title",
        "article_url",
        "cves",
        "withdrawn",
        "parser_version",
        "license",
        "license_url",
        "attribution",
        "warnings",
        "targeting_evidence",
    )
    changed = tuple(f for f in fields if getattr(old[0], f) != getattr(report, f))
    before = {i.id: i for i in old[1]}
    after = {i.id: i for i in items}
    added = tuple(after[k] for k in sorted(after.keys() - before.keys()))
    removed = tuple(before[k] for k in sorted(before.keys() - after.keys()))
    if not changed and not added and not removed:
        return None
    basis = json.dumps(
        [
            report.id,
            report.commit,
            report.parser_version,
            sorted(after),
            {f: report.model_dump(mode="json")[f] for f in fields},
        ],
        sort_keys=True,
    )
    return IocRevision(
        id=identity(basis),
        report_id=report.id,
        observed_at=report.collected_at,
        commit=report.commit,
        parser_version=report.parser_version,
        changed_fields=changed,
        added=added,
        removed=removed,
        attribution=report.attribution,
        license=report.license,
        license_url=report.license_url,
    )


def maintain(
    db: Any, sql: Any, entry: IocRevision | None, postgres: bool, cutoff: datetime
) -> None:
    if entry:
        payload = entry.model_dump_json()
        cast = "::jsonb" if postgres else ""
        db.execute(
            sql(
                f"INSERT INTO threat_feed_ioc_revisions VALUES (?,?,?,?,?{cast}) "
                "ON CONFLICT(id) DO NOTHING"
            ),
            (
                entry.id,
                entry.report_id,
                entry.observed_at.isoformat(),
                len(payload.encode()),
                payload,
            ),
        )
    rows = db.execute(
        "SELECT id,report_id,observed_at,bytes FROM threat_feed_ioc_revisions "
        "ORDER BY observed_at DESC,id DESC"
    ).fetchall()
    counts: dict[str, int] = {}
    size = 0
    for key, report, observed, length in rows:
        counts[report] = counts.get(report, 0) + 1
        if (
            datetime.fromisoformat(observed) < cutoff
            or counts[report] > MAX_REVISIONS
            or size + length > MAX_HISTORY_BYTES
        ):
            db.execute(sql("DELETE FROM threat_feed_ioc_revisions WHERE id=?"), (key,))
            db.execute(
                sql(
                    "INSERT INTO threat_feed_state VALUES (?,?) ON CONFLICT(key) "
                    "DO UPDATE SET value=excluded.value"
                ),
                (f"ioc_history_limited:{report}", "true"),
            )
        else:
            size += length
