"""Bounded personal start-panel projections; never invoke intelligence providers."""

from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel


class RecentWork(BaseModel):
    id: str
    title: str
    updated_at: datetime
    status: str


class ProviderIssue(BaseModel):
    provider: str
    code: Literal["unauthorized", "rate_limited", "upstream_error"]


class StartSummary(BaseModel):
    recent: tuple[RecentWork, ...] = ()
    investigations: int | None = None
    draft_detections: int | None = None
    open_cases: int | None = None
    provider_issues: tuple[ProviderIssue, ...] = ()
    availability: dict[str, bool]
    generated_at: datetime


def start_summary() -> StartSummary:
    from ..system.metrics import registry
    from .routes.cases import get_case_service
    from .routes.workspace import get_workspace_service

    result = StartSummary(
        availability={"workspace": False, "cases": False, "providers": True},
        generated_at=datetime.now(UTC),
    )
    try:
        records = get_workspace_service().snapshot()
        result.investigations = len(records)
        result.draft_detections = sum(
            a.review_status.value == "draft"
            for r in records
            for a in (r.detection_package.artifacts if r.detection_package else ())
        )
        result.recent = tuple(
            RecentWork(id=str(r.id), title=r.title, updated_at=r.updated_at, status=r.status.value)
            for r in sorted(records, key=lambda r: (r.updated_at, str(r.id)), reverse=True)[:5]
        )
        result.availability["workspace"] = True
    except Exception:
        # A broken storage section must not hide other available sections.
        pass
    try:
        result.open_cases = sum(
            c.status.value in {"open", "in_progress"} for c in get_case_service().snapshot()
        )
        result.availability["cases"] = True
    except Exception:
        pass
    latest = {}
    with registry._lock:
        events = list(registry.provider_events)
    for event in reversed(events):
        name = str(event.get("provider", ""))
        if (
            name
            not in {
                "malwarebazaar",
                "urlhaus",
                "abuseipdb",
                "otx",
                "virustotal",
                "shodan",
                "censys",
                "greynoise",
            }
            or name in latest
        ):
            continue
        status = event.get("status_code")
        latest[name] = status
        if status in {401, 403, 429} or isinstance(status, int) and status >= 500:
            code: Literal["unauthorized", "rate_limited", "upstream_error"] = (
                "unauthorized"
                if status in {401, 403}
                else "rate_limited"
                if status == 429
                else "upstream_error"
            )
            result.provider_issues += (ProviderIssue(provider=name, code=code),)
            if len(result.provider_issues) == 5:
                break
    return result
