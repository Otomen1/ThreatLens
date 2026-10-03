"""Public models for the source-attributed Threat Feed."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field, HttpUrl


class FeedRegion(StrEnum):
    GLOBAL = "global"
    MALAYSIA = "malaysia"
    SOUTHEAST_ASIA = "southeast_asia"


class FeedTopic(StrEnum):
    ADVISORY = "advisory"
    VULNERABILITY = "vulnerability"
    ACTIVE_EXPLOITATION = "active_exploitation"
    PHISHING = "phishing"
    RANSOMWARE = "ransomware"
    MALWARE = "malware"
    BREACH = "breach"
    SUPPLY_CHAIN = "supply_chain"
    THREAT_ACTOR = "threat_actor"
    SCAM = "scam"
    RESEARCH = "research"


class FeedEntity(BaseModel):
    type: str
    value: str
    normalized_value: str
    disposition: str = "source-reported"
    verified: bool = False


class ThreatFeedItem(BaseModel):
    id: str
    source_id: str
    source_name: str
    source_kind: str
    guid: str | None = None
    title: str
    excerpt: str = ""
    summary: str
    url: HttpUrl
    published_at: datetime
    collected_at: datetime
    region: FeedRegion
    relevance: str
    region_reasons: tuple[str, ...] = ()
    topic: FeedTopic
    severity: str | None = None
    entities: tuple[FeedEntity, ...] = ()
    vendor: str | None = None
    product: str | None = None


class FeedSourceStatus(BaseModel):
    id: str
    name: str
    kind: str
    enabled: bool = True
    last_success_at: datetime | None = None
    last_attempt_at: datetime | None = None
    last_error_code: str | None = None
    last_error: str | None = None
    last_added: int = 0


class FeedRefreshResult(BaseModel):
    status: str
    started_at: datetime
    completed_at: datetime | None = None
    sources_attempted: int = 0
    sources_succeeded: int = 0
    items_added: int = 0
    items_seen: int = 0
    errors: tuple[str, ...] = ()
    next_refresh_at: datetime | None = None


class FeedListResponse(BaseModel):
    items: tuple[ThreatFeedItem, ...]
    total: int
    page: int
    page_size: int


class RegionCount(BaseModel):
    total: int = 0
    recent: int = 0


class FeedSummary(BaseModel):
    regions: dict[FeedRegion, RegionCount]
    critical: int = 0
    new_iocs: int = 0
    last_refreshed_at: datetime | None = None
    next_refresh_at: datetime | None = None
    source_errors: int = 0


class FeedHomeSection(BaseModel):
    items: tuple[ThreatFeedItem, ...] = ()
    total: int = 0


class FeedHomeResponse(BaseModel):
    summary: FeedSummary
    sections: dict[FeedRegion, FeedHomeSection]
    generated_at: datetime


class SourceEntry(BaseModel):
    guid: str | None = None
    title: str = Field(min_length=1, max_length=500)
    excerpt: str = Field(default="", max_length=4000)
    url: str
    published_at: datetime
    categories: tuple[str, ...] = ()
    severity: str | None = None
    vendor: str | None = None
    product: str | None = None
    known_exploited: bool = False


class VulnerabilityScore(BaseModel):
    source: str
    version: str
    score: float = Field(ge=0, le=10)
    severity: str | None = None


class VulnerabilityReport(BaseModel):
    id: str
    title: str
    url: HttpUrl
    source_id: str
    source_name: str
    published_at: datetime
    excerpt: str = ""
    zero_day: bool = False


class FeedVulnerability(BaseModel):
    id: str
    cve_id: str | None = None
    title: str
    description: str = ""
    published_at: datetime | None = None
    activity_at: datetime
    updated_at: datetime
    products: tuple[str, ...] = ()
    scores: tuple[VulnerabilityScore, ...] = ()
    severity: str | None = None
    sources: tuple[str, ...] = ()
    references: tuple[HttpUrl, ...] = ()
    reports: tuple[VulnerabilityReport, ...] = ()
    reported_zero_day: bool = False
    known_exploited: bool = False
    kev_added_at: datetime | None = None


class VulnerabilityListResponse(BaseModel):
    items: tuple[FeedVulnerability, ...]
    total: int
    page: int
    page_size: int
    published_24h: int = 0
    zero_days_24h: int = 0
    kev_added_24h: int = 0
    sources: tuple[str, ...] = ()
    last_synced_at: datetime | None = None
    sync_status: str = "not_started"
    generated_at: datetime
