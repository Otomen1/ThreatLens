"""Public passive reads; external collection uses the existing leased refresh."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response

from ...ioc_feed.collector import statuses
from ...ioc_feed.models import IndicatorList, IocType, ReportDetail, ReportList, SourceState, Vendor
from ...ioc_feed.service import listing
from ...ioc_feed.storage import IocStorage, get_storage
from .threat_feed import get_threat_feed_service

router = APIRouter(prefix="/api/v1/threat-feed", tags=["ioc-reports"])


def storage() -> IocStorage:
    try:
        return get_storage(get_threat_feed_service().storage)
    except Exception as error:
        raise HTTPException(status_code=503, detail="IOC database is unavailable") from error


@router.get("/ioc-reports", response_model=ReportList)
@router.get("/indicators", response_model=IndicatorList)
def list_records(
    response: Response,
    db: Annotated[IocStorage, Depends(storage)],
    request: Request,
    query: Annotated[str, Query(max_length=200)] = "",
    vendor: Vendor | None = None,
    kind: IocType | None = None,
    hours: Annotated[int, Query(ge=1, le=720)] = 168,
    page: Annotated[int, Query(ge=1, le=10000)] = 1,
    page_size: Annotated[int, Query(ge=1, le=100)] = 20,
) -> ReportList | IndicatorList:
    response.headers["Cache-Control"] = "public, s-maxage=300, stale-while-revalidate=3600"
    return listing(
        db,
        query=query,
        vendor=vendor or "",
        kind=kind or "",
        hours=hours,
        page=page,
        page_size=page_size,
        view="indicators" if request.url.path.endswith("/indicators") else "reports",
    )


@router.get("/ioc-reports/sources", response_model=tuple[SourceState, ...])
def source_statuses(db: Annotated[IocStorage, Depends(storage)]) -> tuple[SourceState, ...]:
    return statuses(db)


@router.get("/ioc-reports/{report_id}", response_model=ReportDetail)
def detail(report_id: str, db: Annotated[IocStorage, Depends(storage)]) -> ReportDetail:
    found = db.detail(report_id)
    if not found:
        raise HTTPException(status_code=404, detail="IOC report not found")
    return ReportDetail(report=found[0], indicators=found[1])


@router.get("/ioc-reports/{report_id}/indicators")
def report_indicators(
    report_id: str,
    db: Annotated[IocStorage, Depends(storage)],
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=100)] = 100,
) -> dict[str, object]:
    found = detail(report_id, db)
    offset = (page - 1) * page_size
    return {
        "items": found.indicators[offset : offset + page_size],
        "total": len(found.indicators),
        "page": page,
        "page_size": page_size,
    }
