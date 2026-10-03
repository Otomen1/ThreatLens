from datetime import datetime
from typing import Literal

from pydantic import BaseModel

Vendor = Literal["talos", "unit42", "eset", "sophoslabs"]
IocType = Literal["ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256"]


class Indicator(BaseModel):
    id: str
    type: IocType
    value: str
    original: str
    disposition: Literal["source-reported"] = "source-reported"
    verified: Literal[False] = False


class IocReport(BaseModel):
    id: str
    vendor: Vendor
    title: str
    path: str
    source_url: str
    article_url: str | None = None
    published_at: datetime | None = None
    activity_at: datetime
    collected_at: datetime
    commit: str
    blob: str
    parser_version: str = "1.0"
    license: str
    license_url: str
    attribution: str
    indicator_count: int = 0
    types: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    withdrawn: bool = False


class SourceState(BaseModel):
    vendor: Vendor
    name: str
    url: str
    enabled: bool
    license: str
    status: str = "not_checked"
    last_success_at: datetime | None = None
    pending: int = 0
    skipped: int = 0
    safe_error: str | None = None
    next_attempt_at: datetime | None = None


class IndicatorRow(Indicator):
    vendors: tuple[str, ...] = ()
    reports: tuple[IocReport, ...] = ()
    activity_at: datetime


class ReportList(BaseModel):
    items: tuple[IocReport, ...]
    total: int
    page: int
    page_size: int
    unique_indicators: int
    recent_indicators: int
    sources: tuple[SourceState, ...]
    generated_at: datetime


class IndicatorList(BaseModel):
    items: tuple[IndicatorRow, ...]
    total: int
    page: int
    page_size: int


class ReportDetail(BaseModel):
    report: IocReport
    indicators: tuple[Indicator, ...]
