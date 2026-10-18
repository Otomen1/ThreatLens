"""Resolve stored feed metadata only; no collection or intelligence requests."""

from datetime import UTC, datetime

from pydantic import ValidationError

from ..ioc_feed.storage import get_storage
from ..threat_feed.logic import clean_text
from ..threat_feed.models import FeedVulnerability
from ..threat_feed.queries import database_backed, run
from ..threat_feed.storage import FeedStorage
from ..threat_feed.vulnerabilities import link_reports
from .models import CaseFeedReference, CaseFeedSource, FeedReferenceKey


def resolve_reference(storage: FeedStorage, key: FeedReferenceKey) -> CaseFeedReference | None:
    title = attribution = ""
    license_name = None
    published = None
    links: list[tuple[str, str]] = []
    record_id = key.id
    if key.kind == "news":
        item = storage.get_item(record_id)
        if item is None:
            return None
        title, published = item.title, item.published_at
        links = [(item.source_name, str(item.url))]
    elif key.kind == "vulnerability":
        if database_backed(storage):
            rows = run(
                storage,
                "SELECT CAST(payload AS text) FROM threat_feed_vulnerabilities "
                "WHERE id IN (?,?) ORDER BY CASE WHEN id=? THEN 0 ELSE 1 END LIMIT 1",
                [record_id.upper(), record_id, record_id.upper()],
            )
            records = [FeedVulnerability.model_validate_json(row[0]) for row in rows]
        else:
            records = link_reports(
                storage.list_vulnerabilities(), storage.list_items(), datetime.now(UTC)
            )
        vulnerability = next((r for r in records if r.id in (record_id, record_id.upper())), None)
        if vulnerability is None:
            return None
        record_id = vulnerability.id
        title, published = vulnerability.title, vulnerability.published_at
        attribution = ", ".join(vulnerability.sources)
        links = [(report.source_name, str(report.url)) for report in vulnerability.reports[:5]]
        links += [("Source reference", str(url)) for url in vulnerability.references[:5]]
    else:
        report = get_storage(storage).get_report(record_id)
        if report is None:
            return None
        title, published = report.title, report.published_at
        attribution, license_name = report.attribution, report.license
        links = [(report.vendor, report.source_url), ("License", report.license_url)]
        if report.article_url:
            links.append(("Original report", report.article_url))
    sources: list[CaseFeedSource] = []
    seen: set[str] = set()
    for name, url in links:
        try:
            source = CaseFeedSource.model_validate(
                {"name": clean_text(name, limit=200) or "Source", "url": url}
            )
        except ValidationError:
            continue
        canonical = str(source.url)
        if canonical not in seen:
            seen.add(canonical)
            sources.append(source)
    return CaseFeedReference(
        kind=key.kind,
        id=record_id,
        title=clean_text(title, limit=500) or "Feed record",
        sources=tuple(sources),
        published_at=published,
        attached_at=datetime.now(UTC),
        attribution=clean_text(attribution, limit=1000),
        license=clean_text(license_name, limit=200) if license_name else None,
    )
