"""Public contracts for private PoC metadata lookup."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, HttpUrl, field_validator

Source = Literal["metasploit", "nuclei"]
Status = Literal["completed", "no_matches", "timed_out", "rate_limited", "busy", "unavailable"]


class LookupRequest(BaseModel):
    cve: str = Field(min_length=13, max_length=32)
    refresh: bool = False

    @field_validator("cve")
    @classmethod
    def normalize_cve(cls, value: str) -> str:
        import re

        normalized = value.strip().upper()
        if not re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,20}", normalized):
            raise ValueError("Enter one valid CVE identifier")
        return normalized


class PocResource(BaseModel):
    source: Source
    id: str
    name: str
    path: str
    kind: Literal["exploit", "auxiliary", "detection", "other"]
    module_type: str | None = None
    description: str = ""
    cves: tuple[str, ...]
    platforms: tuple[str, ...] = ()
    disclosure_date: str | None = None
    modified_at: str | None = None
    check_supported: bool | None = None
    severity: str | None = None
    url: HttpUrl
    verification: Literal["cve_reference_confirmed"] = "cve_reference_confirmed"
    locally_tested: Literal[False] = False


class SourceResult(BaseModel):
    source: Source
    cve: str
    status: Status
    matches: tuple[PocResource, ...] = ()
    total_matches: int = 0
    truncated: bool = False
    checked_at: datetime
    cache_age_seconds: int | None = None
    cached: bool = False
    stale: bool = False
    error_code: str | None = None
    message: str | None = None
    retryable: bool = False
    next_eligible_at: datetime | None = None
    skipped_records: int = 0
