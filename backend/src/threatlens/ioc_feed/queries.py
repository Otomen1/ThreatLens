"""Database-side IOC pagination; hydrate only selected reports/indicators."""

from datetime import UTC, datetime, timedelta
from typing import Any

from ..threat_feed.queries import epoch
from .collector import statuses
from .models import Indicator, IndicatorList, IndicatorRow, IocReport, ReportList
from .parsers import normalize
from .storage import IocStorage


def listing(
    storage: IocStorage,
    *,
    query: str,
    vendor: str,
    kind: str,
    hours: int,
    page: int,
    page_size: int,
    view: str,
    sort: str,
) -> ReportList | IndicatorList:
    now = datetime.now(UTC)
    normalized = normalize(query)
    query = normalized.value if normalized else query.strip()
    report_epoch = epoch(storage.feed, "r.activity_at")
    clauses = [f"{report_epoch}>=?"]
    args: list[Any] = [(now - timedelta(hours=hours)).timestamp()]
    if vendor:
        clauses.append("r.vendor=?")
        args.append(vendor)
    if kind:
        clauses.append(
            "EXISTS(SELECT 1 FROM threat_feed_report_indicators e JOIN "
            "threat_feed_indicators i ON i.id=e.indicator_id WHERE e.report_id=r.id AND i.type=?)"
        )
        args.append(kind)
    if query:
        function = "strpos" if storage.pg else "instr"
        clauses.append(
            f"({function}(LOWER(r.title),?)>0 OR EXISTS(SELECT 1 FROM "
            f"threat_feed_report_indicators e JOIN threat_feed_indicators i ON "
            f"i.id=e.indicator_id WHERE e.report_id=r.id AND i.value=?))"
        )
        args.extend([query.lower(), query])
    group_clauses = ["1=1"]
    if kind:
        group_clauses.append("i.type=?")
        args.append(kind)
    if normalized:
        group_clauses.append("i.id=?")
        args.append(normalized.id)
    direction = "ASC" if sort == "oldest" else "DESC"
    base = (
        f"WITH matched AS (SELECT r.id,r.payload,{report_epoch} AS stamp FROM "
        f"threat_feed_ioc_reports r WHERE {' AND '.join(clauses)}), edges AS "
        f"(SELECT i.id,e.report_id,e.original,i.payload,m.stamp FROM matched m JOIN "
        f"threat_feed_report_indicators e ON e.report_id=m.id JOIN "
        f"threat_feed_indicators i ON i.id=e.indicator_id WHERE "
        f"{' AND '.join(group_clauses)}), groups AS (SELECT id,MAX(stamp) AS stamp "
        f"FROM edges GROUP BY id) "
    )
    if view == "indicators":
        sql = base + (
            f",selected AS (SELECT id FROM groups ORDER BY stamp "
            f"{direction},id {direction} LIMIT ? OFFSET ?) SELECT "
            f"'indicator',e.id,CAST(e.payload AS text),e.original FROM "
            f"edges e JOIN selected s ON s.id=e.id UNION ALL SELECT "
            f"'report',e.id,CAST(m.payload AS text),e.report_id FROM "
            f"edges e JOIN selected s ON s.id=e.id JOIN matched m ON "
            f"m.id=e.report_id UNION ALL SELECT 'total','',CAST(COUNT(*) "
            f"AS text),'' FROM groups"
        )
        params = args + [page_size, (page - 1) * page_size]
    else:
        sql = base + (
            f",selected AS (SELECT payload FROM matched ORDER BY stamp "
            f"{direction},id {direction} LIMIT ? OFFSET ?) SELECT "
            f"'report','',CAST(payload AS text),'' FROM selected UNION "
            f"ALL SELECT 'total','',CAST(COUNT(*) AS text),'' FROM "
            f"matched UNION ALL SELECT 'unique','',CAST(COUNT(*) AS "
            f"text),'' FROM groups UNION ALL SELECT "
            f"'recent','',CAST(COUNT(*) AS text),'' FROM groups WHERE stamp>=?"
        )
        params = args + [page_size, (page - 1) * page_size, (now - timedelta(hours=24)).timestamp()]
    with storage.connection() as db:
        rows = db.execute(storage.sql(sql), params).fetchall()

    def count(key: str) -> int:
        return next((int(r[2]) for r in rows if r[0] == key), 0)

    if view != "indicators":
        reports = [IocReport.model_validate_json(r[2]) for r in rows if r[0] == "report"]
        reports.sort(key=lambda r: (r.activity_at, r.id), reverse=sort != "oldest")
        return ReportList(
            items=tuple(reports),
            total=count("total"),
            page=page,
            page_size=page_size,
            unique_indicators=count("unique"),
            recent_indicators=count("recent"),
            sources=statuses(storage),
            generated_at=now,
        )
    reports_by_id: dict[str, dict[str, IocReport]] = {}
    indicators: dict[str, Indicator] = {}
    for row in rows:
        if row[0] == "indicator":
            indicators[row[1]] = Indicator.model_validate_json(row[2]).model_copy(
                update={"original": row[3]}
            )
        if row[0] == "report":
            record = IocReport.model_validate_json(row[2])
            reports_by_id.setdefault(row[1], {})[record.id] = record
    result = []
    for indicator_id, item in indicators.items():
        reports = sorted(
            reports_by_id[indicator_id].values(),
            key=lambda r: (r.activity_at, r.id),
            reverse=sort != "oldest",
        )
        result.append(
            IndicatorRow(
                **item.model_dump(),
                reports=tuple(reports),
                vendors=tuple(sorted({r.vendor for r in reports})),
                activity_at=max(r.activity_at for r in reports),
            )
        )
    result.sort(key=lambda i: (i.activity_at, i.id), reverse=sort != "oldest")
    return IndicatorList(items=tuple(result), total=count("total"), page=page, page_size=page_size)
