"""Bounded GitHub commit discovery and pinned, metadata-only file collection."""

import asyncio
import copy
import json
import logging
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from urllib.parse import quote, urlsplit

import httpx

from .models import Indicator, IocReport, SourceState, Vendor
from .parsers import (
    MAX_FILE_BYTES,
    article_link,
    identity,
    parse_file,
    supported_path,
    title_from_path,
)
from .storage import IocStorage, StorageCapacity

logger = logging.getLogger("threatlens.ioc_feed")


@dataclass(frozen=True)
class Source:
    vendor: Vendor
    name: str
    repository: str
    license: str
    branch: str
    enabled: bool = True

    @property
    def url(self) -> str:
        return f"https://github.com/{self.repository}"


SOURCES = (
    Source("talos", "Cisco Talos", "Cisco-Talos/IOCs", "CC0-1.0", "main"),
    Source(
        "unit42",
        "Unit 42",
        "PaloAltoNetworks/Unit42-Threat-Intelligence-Article-Information",
        "Unlicense",
        "main",
    ),
    Source("eset", "ESET Research", "eset/malware-ioc", "BSD-2-Clause", "master"),
    Source(
        "sophoslabs",
        "SophosLabs",
        "sophoslabs/IoCs",
        "Redistribution not verified",
        "master",
        False,
    ),
)


class RateLimited(Exception):
    def __init__(self, until: datetime) -> None:
        self.until = until


class BudgetExceeded(Exception):
    pass


class DownloadBudget:
    def __init__(self) -> None:
        self.calls = 0

    async def fetch(self, client: httpx.AsyncClient, url: str, *, api: bool) -> bytes:
        parsed = urlsplit(url)
        host = "api.github.com" if api else "raw.githubusercontent.com"
        repositories = "|".join(re.escape(s.repository) for s in SOURCES)
        prefix = "/repos/" if api else "/"
        suffix = r"/commits(?:/[a-f0-9]{40})?" if api else r"/[a-f0-9]{40}/.+"
        if (
            parsed.scheme != "https"
            or parsed.netloc != host
            or parsed.fragment
            or not re.fullmatch(prefix + f"(?:{repositories})" + suffix, parsed.path)
        ):
            raise ValueError("Unexpected source URL")
        if api:
            if self.calls >= 12:
                raise BudgetExceeded
            self.calls += 1
        cap = 2_000_000 if api else MAX_FILE_BYTES
        async with client.stream("GET", url) as response:
            if response.status_code in {403, 429}:
                reset = response.headers.get("x-ratelimit-reset", "")
                retry = response.headers.get("retry-after", "")
                now = datetime.now(UTC)
                if reset.isdigit():
                    until = datetime.fromtimestamp(
                        min(int(reset), int(now.timestamp()) + 86400), UTC
                    )
                else:
                    until = now + timedelta(
                        seconds=min(int(retry), 86400) if retry.isdigit() else 3600
                    )
                raise RateLimited(max(now + timedelta(seconds=60), until))
            response.raise_for_status()
            body = bytearray()
            async for chunk in response.aiter_bytes():
                body.extend(chunk)
                if len(body) > cap:
                    raise ValueError("Source payload exceeded limit")
        return bytes(body)


def statuses(storage: IocStorage) -> tuple[SourceState, ...]:
    result = []
    for source in SOURCES:
        raw = storage.feed.state(f"ioc_status:{source.vendor}")
        result.append(
            SourceState.model_validate_json(raw)
            if raw
            else SourceState(
                vendor=source.vendor,
                name=source.name,
                url=source.url,
                enabled=source.enabled,
                license=source.license,
                status="not_checked" if source.enabled else "license_pending",
                safe_error=None
                if source.enabled
                else "Import disabled pending redistribution review.",
            )
        )
    return tuple(result)


async def collect_source(
    storage: IocStorage, source: Source, budget: DownloadBudget, now: datetime
) -> int:
    if not source.enabled:
        return 0
    key = f"ioc_cursor:{source.vendor}"
    status_key = f"ioc_status:{source.vendor}"
    previous = next(s for s in statuses(storage) if s.vendor == source.vendor)
    if previous.next_attempt_at and previous.next_attempt_at > now:
        return 0
    state = json.loads(storage.feed.state(key) or "{}")
    state.setdefault("since", (now - timedelta(days=30)).isoformat())
    state.setdefault("until", now.isoformat())
    state.setdefault("page", 1)
    state.setdefault("commits", [])
    state.setdefault("files", [])
    skipped = 0
    added = 0
    safe_error = None
    next_attempt = None
    status = "partial"
    try:
        async with (
            asyncio.timeout(55),
            httpx.AsyncClient(
                timeout=10,
                follow_redirects=False,
                headers={
                    "Accept": "application/vnd.github+json",
                    "User-Agent": "ThreatLens-IOC-Reports",
                },
            ) as client,
        ):
            if not state["commits"] and not state["files"] and not state.get("discovered"):
                params = httpx.QueryParams(
                    {
                        "since": state["since"],
                        "until": state["until"],
                        "per_page": 100,
                        "page": state["page"],
                    }
                )
                payload = await budget.fetch(
                    client,
                    f"https://api.github.com/repos/{source.repository}/commits?{params}",
                    api=True,
                )
                commits = json.loads(payload)
                if not isinstance(commits, list) or len(commits) > 100:
                    raise ValueError("Unexpected commit response")
                state["commits"] = [
                    {"sha": c["sha"], "date": c["commit"]["committer"]["date"]} for c in commits
                ]
                state["discovered"] = len(commits) < 100
                state["page"] += 1
                # Persist discovery, but do not advance the successful window cursor.
                storage.feed.set_state(key, json.dumps(state))
            if not state["files"] and state["commits"]:
                commit = state["commits"][0]
                if not re.fullmatch(r"[0-9a-f]{40}", commit["sha"]):
                    raise ValueError("Invalid commit identity")
                payload = await budget.fetch(
                    client,
                    f"https://api.github.com/repos/{source.repository}/commits/{commit['sha']}",
                    api=True,
                )
                metadata = json.loads(payload)
                files = metadata.get("files")
                if not isinstance(files, list) or len(files) >= 300:
                    raise ValueError("Commit files truncated or malformed")
                state["files"] = [
                    {
                        "path": f["filename"],
                        "blob": f.get("sha", ""),
                        "removed": f.get("status") == "removed",
                    }
                    for f in files
                    if supported_path(source.vendor, f.get("filename", ""))
                ]
                skipped = len(files) - len(state["files"])
                storage.feed.set_state(key, json.dumps(state))
            for _ in range(5):
                if not state["files"]:
                    break
                file = state["files"][0]
                commit = state["commits"][0]
                path = file["path"]
                report_id = identity(f"{source.vendor}:{path}")
                date = datetime.fromisoformat(commit["date"].replace("Z", "+00:00"))
                if date.tzinfo is None:
                    raise ValueError("Missing timezone")
                old = storage.detail(report_id)
                if old and old[0].activity_at >= date:
                    state["files"].pop(0)
                    storage.feed.set_state(key, json.dumps(state))
                    continue
                indicators: tuple[Indicator, ...]
                warnings: tuple[str, ...]
                article = old[0].article_url if old else None
                if file["removed"]:
                    indicators, warnings = (
                        (),
                        ("Source file removed; indicators are no longer in its current list.",),
                    )
                else:
                    payload = await budget.fetch(
                        client,
                        f"https://raw.githubusercontent.com/{source.repository}/"
                        f"{commit['sha']}/{quote(path, safe='/')}",
                        api=False,
                    )
                    indicators, warnings = await asyncio.to_thread(
                        parse_file, source.vendor, path, payload
                    )
                    article = article_link(source.vendor, payload) or article
                    if not indicators and old:
                        # An unsupported new format must not erase a previously parsed list.
                        # Explicit repository deletions are handled separately above.
                        raise ValueError("Updated file has no parseable indicators")
                    if not indicators and not old:
                        skipped += 1
                        state["files"].pop(0)
                        storage.feed.set_state(key, json.dumps(state))
                        continue
                report = IocReport(
                    id=report_id,
                    vendor=source.vendor,
                    title=title_from_path(path),
                    path=path,
                    article_url=article,
                    source_url=f"{source.url}/blob/{commit['sha']}/{quote(path, safe='/')}",
                    activity_at=date,
                    collected_at=now,
                    commit=commit["sha"],
                    blob=file["blob"],
                    license=source.license,
                    license_url=f"{source.url}/blob/{source.branch}/LICENSE",
                    attribution=f"Indicators published by {source.name}; "
                    "source-reported, not independently verified.",
                    warnings=warnings,
                    withdrawn=file["removed"],
                )
                committed_state = copy.deepcopy(state)
                committed_state["files"].pop(0)
                # File and resume state commit together. Failed writes cannot skip work.
                storage.save(report, indicators, {key: json.dumps(committed_state)})
                state = committed_state
                added += 1
            if not state["files"] and state["commits"]:
                state["commits"].pop(0)
            if not state["files"] and not state["commits"] and state.get("discovered"):
                state = {
                    "since": state["until"],
                    "until": now.isoformat(),
                    "page": 1,
                    "commits": [],
                    "files": [],
                }
                status = "current"
    except RateLimited as error:
        status, safe_error, next_attempt = (
            "rate_limited",
            "GitHub request limit reached; waiting for the next eligible refresh.",
            error.until,
        )
    except StorageCapacity:
        status, safe_error = (
            "storage_limited",
            "Local storage budget reached; pending work retained.",
        )
    except BudgetExceeded:
        status, safe_error = "partial", "Refresh request budget reached; pending work is retained."
    except (TimeoutError, httpx.TimeoutException):
        status, safe_error = (
            "timed_out",
            "Source collection timed out; previous reports remain available.",
        )
    except Exception:
        logger.warning("IOC collection unavailable: source=%s", source.vendor)
        status, safe_error = (
            "unavailable",
            "Source format or storage is unavailable; pending work is retained.",
        )
    storage.feed.set_state(key, json.dumps(state))
    outcome = SourceState(
        vendor=source.vendor,
        name=source.name,
        url=source.url,
        enabled=True,
        license=source.license,
        status=status,
        last_success_at=now if status in {"current", "partial"} else previous.last_success_at,
        pending=len(state["files"]) + len(state["commits"]),
        skipped=skipped,
        safe_error=safe_error,
        next_attempt_at=next_attempt,
    )
    storage.feed.set_state(status_key, outcome.model_dump_json())
    return added


async def collect(storage: IocStorage, now: datetime) -> int:
    budget = DownloadBudget()
    results = await asyncio.gather(
        *(collect_source(storage, source, budget, now) for source in SOURCES),
        return_exceptions=True,
    )
    storage.prune(now - timedelta(days=30))
    return sum(result for result in results if isinstance(result, int))
