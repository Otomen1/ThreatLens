"""CVE records, explicit zero-day reports and bounded incremental NVD collection."""

from __future__ import annotations

import asyncio
import json
import re
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import unquote, urlsplit

import httpx
from pydantic import HttpUrl

from .logic import clean_text
from .models import (
    FeedSourceStatus,
    FeedTopic,
    FeedVulnerability,
    ThreatFeedItem,
    VulnerabilityListResponse,
    VulnerabilityReport,
    VulnerabilityScore,
)
from .storage import FeedStorage

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)
ZERO_DAY = re.compile(r"\bzero[\s-]day\b|\b0[\s-]day\b", re.I)
MAX_NVD_BYTES = 8_000_000
PAGE_SIZE = 500


def utc_date(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)


def safe_url(value: str) -> HttpUrl | None:
    try:
        parsed = urlsplit(value)
        if parsed.username or parsed.password or parsed.scheme not in {"https", "http"}:
            return None
        return HttpUrl(value)
    except ValueError:
        return None


def products_from_configurations(nodes: Any) -> tuple[str, ...]:
    products: set[str] = set()

    def walk(value: Any, depth: int = 0) -> None:
        if depth > 12 or len(products) >= 40:
            return
        if isinstance(value, list):
            for child in value[:100]:
                walk(child, depth + 1)
        elif isinstance(value, dict):
            if value.get("vulnerable") is True:
                criteria = value.get("criteria", "")
                if isinstance(criteria, str):
                    parts = criteria.split(":")
                    if len(parts) > 4:
                        products.add(clean_text(unquote(f"{parts[3]} {parts[4]}"), limit=200))
            for key in ("nodes", "children", "cpeMatch"):
                walk(value.get(key), depth + 1)

    walk(nodes)
    return tuple(sorted(products))


def parse_nvd(row: dict[str, Any], now: datetime) -> FeedVulnerability | None:
    cve_id = str(row.get("id", "")).upper()
    if not CVE.fullmatch(cve_id) or row.get("vulnStatus") == "Rejected":
        return None
    published = utc_date(str(row["published"]))
    modified = utc_date(str(row.get("lastModified", row["published"])))
    description = next(
        (
            clean_text(str(item.get("value", "")), limit=3000)
            for item in row.get("descriptions", [])
            if item.get("lang") == "en"
        ),
        "",
    )
    scores: list[VulnerabilityScore] = []
    for name in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for metric in row.get("metrics", {}).get(name, [])[:10]:
            data = metric.get("cvssData", {})
            score = data.get("baseScore")
            if isinstance(score, (float, int)) and not isinstance(score, bool) and 0 <= score <= 10:
                severity = data.get("baseSeverity", metric.get("baseSeverity"))
                scores.append(
                    VulnerabilityScore(
                        source=clean_text(str(metric.get("source", "NVD")), limit=150),
                        version=str(data.get("version", "unknown")),
                        score=score,
                        severity=str(severity).lower() if severity else None,
                    )
                )
    preferred = scores[0] if scores else None
    links = [HttpUrl(f"https://nvd.nist.gov/vuln/detail/{cve_id}")]
    for reference in row.get("references", [])[:20]:
        link = safe_url(str(reference.get("url", "")))
        if link and link not in links:
            links.append(link)
    kev_date = row.get("cisaExploitAdd")
    kev_added = utc_date(str(kev_date)) if kev_date else None
    return FeedVulnerability(
        id=cve_id,
        cve_id=cve_id,
        title=cve_id,
        description=description,
        published_at=published,
        activity_at=max(published, kev_added or published),
        updated_at=min(modified, now),
        scores=tuple(scores),
        severity=preferred.severity if preferred else None,
        products=products_from_configurations(row.get("configurations", [])),
        sources=("NVD",),
        references=tuple(links),
        known_exploited=bool(kev_added),
        kev_added_at=kev_added,
    )


def merge_record(old: FeedVulnerability | None, new: FeedVulnerability) -> FeedVulnerability:
    if old is None:
        return new
    reports = {report.id: report for report in old.reports}
    reports.update({report.id: report for report in new.reports})
    return new.model_copy(
        update={
            "description": new.description or old.description,
            "published_at": new.published_at or old.published_at,
            "title": new.title if new.title != new.cve_id else old.title,
            "products": tuple(sorted(set(old.products + new.products))),
            "scores": new.scores or old.scores,
            "severity": new.severity or old.severity,
            "sources": tuple(sorted(set(old.sources + new.sources))),
            "references": tuple(dict.fromkeys(old.references + new.references)),
            "reports": tuple(sorted(reports.values(), key=lambda r: r.published_at, reverse=True)),
            "reported_zero_day": old.reported_zero_day or new.reported_zero_day,
            "known_exploited": old.known_exploited or new.known_exploited,
            "kev_added_at": new.kev_added_at or old.kev_added_at,
            "activity_at": max(old.activity_at, new.activity_at),
            "updated_at": max(old.updated_at, new.updated_at),
        }
    )


def link_reports(
    records: list[FeedVulnerability], items: list[ThreatFeedItem], now: datetime
) -> list[FeedVulnerability]:
    grouped = {record.id: record for record in records}
    for item in items:
        text = f"{item.title} {item.excerpt} {item.summary}"
        cves = sorted({value.upper() for value in CVE.findall(text)})
        zero_day = bool(ZERO_DAY.search(text))
        if (
            not cves
            and not zero_day
            and item.topic
            not in {
                FeedTopic.VULNERABILITY,
                FeedTopic.ACTIVE_EXPLOITATION,
            }
        ):
            continue
        report = VulnerabilityReport(
            id=item.id,
            title=item.title,
            url=item.url,
            source_id=item.source_id,
            source_name=item.source_name,
            published_at=item.published_at,
            excerpt=clean_text(item.excerpt or item.summary, limit=1200),
            zero_day=zero_day,
        )
        for record_id in cves or [f"report-{item.id}"]:
            old = grouped.get(record_id)
            kev = item.source_id == "cisa_kev"
            cve_id = record_id if CVE.fullmatch(record_id) else None
            record = FeedVulnerability(
                id=record_id,
                cve_id=cve_id,
                title=item.title,
                description=item.excerpt or item.summary,
                activity_at=item.published_at,
                updated_at=item.collected_at,
                severity=item.severity,
                products=tuple(filter(None, [f"{item.vendor or ''} {item.product or ''}".strip()])),
                sources=(item.source_name,),
                references=(item.url,),
                reports=(report,),
                reported_zero_day=zero_day,
                known_exploited=kev,
                kev_added_at=item.published_at if kev else None,
            )
            # Publisher reports enrich official CVE data; they do not replace it.
            grouped[record_id] = merge_record(record, old) if old else record
    cutoff = now - timedelta(days=30)
    return [
        record.model_copy(
            update={
                "reports": tuple(
                    report for report in record.reports if report.published_at >= cutoff
                ),
            }
        )
        for record in grouped.values()
        if record.activity_at >= cutoff
    ]


async def fetch_nvd_page(params: dict[str, str]) -> dict[str, Any]:
    async with (
        httpx.AsyncClient(timeout=20, follow_redirects=False) as client,
        client.stream("GET", NVD_URL, params=params) as response,
    ):
        response.raise_for_status()
        body = bytearray()
        async for chunk in response.aiter_bytes():
            body.extend(chunk)
            if len(body) > MAX_NVD_BYTES:
                raise ValueError("NVD payload exceeded limit")
    payload: Any = json.loads(body)
    if not isinstance(payload, dict) or not isinstance(payload.get("vulnerabilities"), list):
        raise ValueError("Invalid NVD response")
    return dict(payload)


async def sync_nvd(storage: FeedStorage, now: datetime) -> None:
    pending = storage.state("nvd_pending")
    if pending:
        window = json.loads(pending)
    else:
        cursor = storage.state("nvd_cursor")
        start = utc_date(cursor) - timedelta(minutes=5) if cursor else now - timedelta(days=7)
        # NVD permits date windows of at most 120 days; resume long outages in chunks.
        end = min(now, start + timedelta(days=119))
        window = {
            "start": start.isoformat(),
            "end": end.isoformat(),
            "index": 0,
            "mode": "lastMod" if cursor else "pub",
        }
    records = {record.id: record for record in storage.list_vulnerabilities()}
    original_ids = set(records)
    for page in range(3):
        if page:
            await asyncio.sleep(6)
        else:
            last_request = storage.state("nvd_last_request")
            if last_request:
                elapsed = (datetime.now(UTC) - utc_date(last_request)).total_seconds()
                if elapsed < 6:
                    await asyncio.sleep(min(6, 6 - elapsed))
        params = {
            f"{window['mode']}StartDate": window["start"],
            f"{window['mode']}EndDate": window["end"],
            "startIndex": str(window["index"]),
            "resultsPerPage": str(PAGE_SIZE),
        }
        # Persist attempts as well as successes to protect rapid scheduled/manual retries.
        storage.set_state("nvd_last_request", datetime.now(UTC).isoformat())
        payload = await fetch_nvd_page(params)
        rows = payload["vulnerabilities"]
        page_records: dict[str, FeedVulnerability] = {}
        for row in rows:
            record = parse_nvd(row["cve"], now)
            if record and (record.activity_at >= now - timedelta(days=30) or record.id in records):
                records[record.id] = merge_record(records.get(record.id), record)
                page_records[record.id] = records[record.id]
        next_index = int(payload.get("startIndex", window["index"])) + len(rows)
        complete = next_index >= int(payload["totalResults"])
        if not rows and not complete:
            raise ValueError("NVD pagination did not advance")
        window["index"] = next_index
        state = {
            "nvd_pending": "" if complete else json.dumps(window),
            "nvd_status": "current" if complete and utc_date(window["end"]) >= now else "partial",
            "nvd_last_success": now.isoformat(),
        }
        if complete:
            state["nvd_cursor"] = window["end"]
        storage.save_vulnerabilities(page_records.values(), state=state)
        if complete:
            break
    storage.save_source(
        FeedSourceStatus(
            id="nvd",
            name="NVD",
            kind="json",
            last_attempt_at=now,
            last_success_at=now,
            last_added=len(set(records) - original_ids),
        )
    )


def vulnerability_list(
    storage: FeedStorage,
    *,
    query: str = "",
    category: str = "all",
    severity: str = "",
    source: str = "",
    hours: int = 168,
    page: int = 1,
    page_size: int = 20,
) -> VulnerabilityListResponse:
    now = datetime.now(UTC)
    records = link_reports(storage.list_vulnerabilities(), storage.list_items(), now)
    cutoff = now - timedelta(hours=hours)
    recent = now - timedelta(hours=24)
    needle = query.strip().lower()
    matching = [
        record
        for record in records
        if record.activity_at >= cutoff
        and (not source or source in record.sources)
        and (not severity or record.severity == severity)
        and (
            not needle
            or needle
            in (
                f"{record.title} {record.cve_id} {record.description} {' '.join(record.products)}"
            ).lower()
        )
        and (
            category == "all"
            or category == "new_cves"
            and record.published_at is not None
            and record.published_at >= cutoff
            or category == "zero_days"
            and record.reported_zero_day
            or category == "known_exploited"
            and record.known_exploited
        )
    ]
    matching.sort(key=lambda record: (record.activity_at, record.id), reverse=True)
    start = (page - 1) * page_size
    last = storage.state("nvd_last_success")
    return VulnerabilityListResponse(
        items=tuple(matching[start : start + page_size]),
        total=len(matching),
        page=page,
        page_size=page_size,
        published_24h=sum(r.published_at is not None and r.published_at >= recent for r in records),
        zero_days_24h=sum(
            any(p.zero_day and p.published_at >= recent for p in r.reports) for r in records
        ),
        kev_added_24h=sum(r.kev_added_at is not None and r.kev_added_at >= recent for r in records),
        sources=tuple(sorted({source for r in records for source in r.sources})),
        sync_status=storage.state("nvd_status") or "not_started",
        last_synced_at=utc_date(last) if last else None,
        generated_at=now,
    )
