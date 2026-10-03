"""Passive, source-attributed workflow views. No external requests."""

import re
import time
from collections import OrderedDict
from datetime import UTC, datetime, timedelta
from threading import Lock
from typing import Literal
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

from pydantic import BaseModel

from ..ioc_feed.collector import SOURCES as IOC_SOURCES
from ..ioc_feed.collector import statuses
from ..ioc_feed.parsers import normalize
from ..ioc_feed.storage import get_storage
from .sources import SOURCES
from .storage import FeedStorage

RecordKind = Literal["news", "vulnerability", "ioc"]


def canonical_url(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme not in {"https", "http"} or parsed.username or parsed.password:
        return ""
    path = parsed.path.rstrip("/")
    query = urlencode(
        [
            (k, v)
            for k, v in parse_qsl(parsed.query)
            if not k.lower().startswith("utm_") and k.lower() not in {"gclid", "fbclid"}
        ]
    )
    if not path and not query:
        return ""
    return urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), path or "/", query, ""))


class FeedReference(BaseModel):
    kind: RecordKind
    id: str
    title: str
    href: str
    activity_at: datetime
    source: str
    cves: tuple[str, ...] = ()
    indicators: tuple[str, ...] = ()
    urls: tuple[str, ...] = ()
    text: str = ""


class SearchGroup(BaseModel):
    items: tuple[FeedReference, ...]
    total: int
    page: int
    page_size: int = 20


class FeedSearch(BaseModel):
    groups: dict[str, SearchGroup]
    generated_at: datetime
    poc_cve: str | None = None


class RelatedReference(BaseModel):
    record: FeedReference
    reason: str
    supporting_values: tuple[str, ...]


class FeedRelated(BaseModel):
    items: tuple[RelatedReference, ...]
    cves: tuple[str, ...]


_cache: OrderedDict[tuple[object, ...], tuple[float, FeedSearch | FeedRelated]] = OrderedDict()
_cache_lock = Lock()


def clear_workflow_cache() -> None:
    with _cache_lock:
        _cache.clear()


def _remember(key: tuple[object, ...], result: FeedSearch | FeedRelated) -> None:
    with _cache_lock:
        _cache[key] = (time.monotonic() + 300, result)
        _cache.move_to_end(key)
        while len(_cache) > 32:
            _cache.popitem(last=False)


def search(
    storage: FeedStorage, query: str, pages: dict[str, int], oldest: bool = False
) -> FeedSearch:
    key = (id(storage), "search", query.strip(), tuple(sorted(pages.items())), oldest)
    with _cache_lock:
        found = _cache.get(key)
        if found and found[0] > time.monotonic() and isinstance(found[1], FeedSearch):
            return found[1]
    result = _search(storage, query, pages, oldest)
    _remember(key, result)
    return result


def related(storage: FeedStorage, kind: RecordKind, record_id: str) -> FeedRelated | None:
    key = (id(storage), "related", kind, record_id)
    with _cache_lock:
        found = _cache.get(key)
        if found and found[0] > time.monotonic() and isinstance(found[1], FeedRelated):
            return found[1]
    result = _related(storage, kind, record_id)
    if result is not None:
        _remember(key, result)
    return result


def cve(value: str) -> str | None:
    value = value.strip().upper()
    return value if re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,20}", value) else None


def references(storage: FeedStorage) -> list[FeedReference]:
    now = datetime.now(UTC)
    cutoff = now - timedelta(days=30)
    records: list[FeedReference] = []
    for item in storage.list_items():
        if item.published_at < cutoff:
            continue
        records.append(
            FeedReference(
                kind="news",
                id=item.id,
                title=item.title,
                href=f"/threat-feed/{quote(item.id, safe='')}",
                activity_at=item.published_at,
                source=item.source_name,
                cves=tuple(
                    sorted(
                        {v for e in item.entities if (v := cve(e.normalized_value))}
                        | {
                            v.upper()
                            for v in re.findall(
                                r"\bCVE-\d{4}-\d{4,20}\b", f"{item.title} {item.excerpt}", re.I
                            )
                        }
                    )
                )[:100],
                indicators=tuple(
                    sorted({n.value for e in item.entities if (n := normalize(e.normalized_value))})
                ),
                urls=(canonical_url(str(item.url)),),
                text=" ".join(
                    [item.title, item.excerpt, item.summary, item.vendor or "", item.product or ""]
                ),
            )
        )
    for vulnerability in storage.list_vulnerabilities():
        if vulnerability.activity_at < cutoff:
            continue
        records.append(
            FeedReference(
                kind="vulnerability",
                id=vulnerability.id,
                title=vulnerability.title,
                href=f"/threat-feed/vulnerabilities/{quote(vulnerability.id, safe='')}",
                activity_at=vulnerability.activity_at,
                source=", ".join(vulnerability.sources),
                cves=(vulnerability.cve_id,) if vulnerability.cve_id else (),
                urls=tuple(canonical_url(str(r.url)) for r in vulnerability.reports),
                text=" ".join(
                    [vulnerability.title, vulnerability.description, *vulnerability.products]
                ),
            )
        )
    for report, items in get_storage(storage).snapshot(query="", vendor="", kind="", cutoff=cutoff):
        records.append(
            FeedReference(
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
        )
    return records


def _search(
    storage: FeedStorage, query: str, pages: dict[str, int], oldest: bool = False
) -> FeedSearch:
    records = references(storage)
    normalized_cve = cve(query)
    observable = normalize(query)

    def matches(record: FeedReference) -> bool:
        if normalized_cve:
            return normalized_cve in record.cves
        if observable:
            return observable.value in record.indicators
        return bool(query.strip()) and query.casefold().strip() in record.text.casefold()

    groups = {}
    for kind in ("news", "vulnerability", "ioc"):
        items = sorted(
            (r for r in records if r.kind == kind and matches(r)),
            key=lambda r: (r.activity_at, r.id),
            reverse=not oldest,
        )
        page = pages.get(kind, 1)
        groups[kind] = SearchGroup(
            items=tuple(
                r.model_copy(update={"indicators": (), "text": "", "urls": ()})
                for r in items[(page - 1) * 20 : page * 20]
            ),
            total=len(items),
            page=page,
        )
    return FeedSearch(groups=groups, generated_at=datetime.now(UTC), poc_cve=normalized_cve)


def _related(storage: FeedStorage, kind: RecordKind, record_id: str) -> FeedRelated | None:
    records = references(storage)
    source = next((r for r in records if r.kind == kind and r.id == record_id), None)
    if source is None:
        return None
    result = []
    for record in records:
        if record.kind == kind and record.id == record_id:
            continue
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
    result.sort(key=lambda r: r.record.activity_at, reverse=True)
    return FeedRelated(items=tuple(result[:100]), cves=source.cves)


class SourceCoverage(BaseModel):
    id: str
    name: str
    collection: Literal["news", "vulnerabilities", "iocs"]
    state: str
    stale: bool = False
    last_attempt_at: datetime | None = None
    last_success_at: datetime | None = None
    pending: int = 0
    error: str | None = None
    next_eligible_at: datetime | None = None


class FeedCoverage(BaseModel):
    sources: tuple[SourceCoverage, ...]
    generated_at: datetime
    next_refresh_at: datetime | None = None
    poc_policy: str = "PoC freshness follows its checked time and cache flags, not feed scheduling."


def timestamp(value: str | None) -> datetime | None:
    try:
        result = datetime.fromisoformat(value) if value else None
        return result if result and result.tzinfo else None
    except ValueError:
        return None


def coverage(storage: FeedStorage, now: datetime | None = None) -> FeedCoverage:
    now = now or datetime.now(UTC)
    previous = {s.id: s for s in storage.list_sources()}
    attempt = timestamp(storage.state("last_refresh_attempt"))
    next_refresh = attempt + timedelta(minutes=30) if attempt else None
    result: list[SourceCoverage] = []
    for source in SOURCES:
        record = previous.get(source.id)
        success = record.last_success_at if record else None
        state = "never_checked"
        if record:
            state = (
                "disabled" if not record.enabled else "failed" if record.last_error else "current"
            )
        result.append(
            SourceCoverage(
                id=source.id,
                name=source.name,
                collection="news",
                state=state,
                stale=bool(success and now - success > timedelta(hours=8)),
                last_attempt_at=record.last_attempt_at if record else None,
                last_success_at=success,
                error=record.last_error if record else None,
                next_eligible_at=next_refresh,
            )
        )
    success = timestamp(storage.state("nvd_last_success"))
    nvd = previous.get("nvd")
    result.append(
        SourceCoverage(
            id="nvd",
            name="NVD",
            collection="vulnerabilities",
            state=storage.state("nvd_status") or "never_checked",
            stale=bool(success and now - success > timedelta(hours=8)),
            last_attempt_at=timestamp(storage.state("nvd_last_request")),
            last_success_at=success,
            pending=int(bool(storage.state("nvd_pending"))),
            error=nvd.last_error if nvd else None,
            next_eligible_at=next_refresh,
        )
    )
    try:
        for s in statuses(get_storage(storage)):
            result.append(
                SourceCoverage(
                    id=s.vendor,
                    name=s.name,
                    collection="iocs",
                    state=s.status if s.enabled else "disabled",
                    stale=bool(s.last_success_at and now - s.last_success_at > timedelta(hours=8)),
                    last_attempt_at=s.last_attempt_at,
                    last_success_at=s.last_success_at,
                    pending=s.pending,
                    error=s.safe_error,
                    next_eligible_at=s.next_attempt_at or next_refresh,
                )
            )
    except Exception:
        result.extend(
            SourceCoverage(
                id=s.vendor,
                name=s.name,
                collection="iocs",
                state="unavailable" if s.enabled else "disabled",
                error="IOC database unavailable" if s.enabled else "Redistribution review pending",
            )
            for s in IOC_SOURCES
        )
    return FeedCoverage(sources=tuple(result), generated_at=now, next_refresh_at=next_refresh)
