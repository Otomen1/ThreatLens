"""Cached public reads without triggering external requests."""

import time
from collections import OrderedDict
from datetime import UTC, datetime, timedelta
from threading import Lock

from .collector import statuses
from .models import IndicatorList, IndicatorRow, ReportList
from .parsers import normalize
from .storage import IocStorage

_cache: OrderedDict[
    tuple[int, str, str, str, int, int, int, str], tuple[float, ReportList | IndicatorList]
] = OrderedDict()
_lock = Lock()


def clear_cache() -> None:
    with _lock:
        _cache.clear()


def listing(
    storage: IocStorage,
    *,
    query: str = "",
    vendor: str = "",
    kind: str = "",
    hours: int = 168,
    page: int = 1,
    page_size: int = 20,
    view: str = "reports",
) -> ReportList | IndicatorList:
    key = (id(storage), query, vendor, kind, hours, page, page_size, view)
    with _lock:
        cached = _cache.get(key)
        if cached and cached[0] > time.monotonic():
            return cached[1]
    now = datetime.now(UTC)
    normalized = normalize(query)
    query = normalized.value if normalized else query.strip()
    records = storage.snapshot(
        query=query, vendor=vendor, kind=kind, cutoff=now - timedelta(hours=hours)
    )
    groups: dict[str, IndicatorRow] = {}
    for report, indicators in records:
        for item in indicators:
            if (kind and item.type != kind) or (normalized and item.id != normalized.id):
                continue
            old = groups.get(item.id)
            groups[item.id] = IndicatorRow(
                **item.model_dump(),
                vendors=tuple(sorted(set((old.vendors if old else ()) + (report.vendor,)))),
                reports=(old.reports if old else ()) + (report,),
                activity_at=max(old.activity_at, report.activity_at) if old else report.activity_at,
            )
    offset = (page - 1) * page_size
    result: ReportList | IndicatorList
    if view == "indicators":
        items = sorted(groups.values(), key=lambda item: (item.activity_at, item.id), reverse=True)
        result = IndicatorList(
            items=tuple(items[offset : offset + page_size]),
            total=len(items),
            page=page,
            page_size=page_size,
        )
    else:
        result = ReportList(
            items=tuple(r for r, _ in records[offset : offset + page_size]),
            total=len(records),
            page=page,
            page_size=page_size,
            unique_indicators=len(groups),
            recent_indicators=sum(
                i.activity_at >= now - timedelta(hours=24) for i in groups.values()
            ),
            sources=statuses(storage),
            generated_at=now,
        )
    with _lock:
        _cache[key] = (time.monotonic() + 300, result)
        _cache.move_to_end(key)
        while len(_cache) > 32:
            _cache.popitem(last=False)
    return result
