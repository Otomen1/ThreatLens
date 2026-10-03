"""Fixed-host metadata adapters. No module, template, or exploit code is fetched."""

from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

import httpx
from pydantic import HttpUrl

from ..threat_feed.logic import clean_text
from .models import PocResource, Source

URLS: dict[Source, str] = {
    "metasploit": "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json",
    "nuclei": "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves.json",
}
LIMITS: dict[Source, int] = {"metasploit": 16_000_000, "nuclei": 8_000_000}
CVE = re.compile(r"CVE-\d{4}-\d{4,20}", re.ASCII)


@dataclass(frozen=True)
class MetadataIndex:
    records: tuple[PocResource, ...]
    skipped: int = 0


def safe_path(value: Any, *, source: Source) -> str:
    if not isinstance(value, str) or len(value) > 350:
        raise ValueError("Invalid resource path")
    if not re.fullmatch(r"[A-Za-z0-9_./-]+", value):
        raise ValueError("Invalid resource path")
    if any(part in {"", ".", ".."} for part in value.split("/")):
        raise ValueError("Invalid resource path")
    if source == "metasploit" and not (value.startswith("modules/") and value.endswith(".rb")):
        raise ValueError("Unexpected module path")
    if source == "nuclei" and not value.endswith((".yaml", ".yml")):
        raise ValueError("Unexpected template path")
    return value


def cve_refs(values: Any) -> tuple[str, ...]:
    if isinstance(values, str):
        values = values.split(",")
    if not isinstance(values, list):
        return ()
    return tuple(
        sorted(
            {
                value.strip().upper()
                for value in values[:100]
                if isinstance(value, str) and CVE.fullmatch(value.strip().upper())
            }
        )
    )


def text(value: Any, limit: int = 1000) -> str:
    return clean_text(value, limit=limit) if isinstance(value, str) else ""


def metasploit_row(row: dict[str, Any]) -> PocResource | None:
    refs = cve_refs(row.get("references"))
    if not refs:
        return None
    fullname = row.get("fullname")
    module_type = text(row.get("type"), 40)
    path = row.get("path", "")
    if not isinstance(path, str) or not path.startswith("modules/"):
        # Framework metadata can contain installation-local paths. Derive the
        # official repository path only from its explicit canonical fullname.
        if not isinstance(fullname, str) or "/" not in fullname:
            raise ValueError("Missing module identity")
        category, remainder = fullname.split("/", 1)
        folder = {
            "exploit": "exploits",
            "payload": "payloads",
            "encoder": "encoders",
            "nop": "nops",
            "auxiliary": "auxiliary",
            "post": "post",
            "evasion": "evasion",
        }.get(category)
        if not folder:
            raise ValueError("Unsupported module identity")
        path = f"modules/{folder}/{remainder}.rb"
    path = safe_path(path, source="metasploit")
    platform = row.get("platform")
    platforms = (
        tuple(text(v, 100) for v in platform[:20] if isinstance(v, str))
        if isinstance(platform, list)
        else ((text(platform, 200),) if isinstance(platform, str) else ())
    )
    return PocResource(
        source="metasploit",
        id=path,
        path=path,
        name=text(row.get("name"), 250) or text(fullname, 250) or path,
        kind="exploit"
        if module_type == "exploit"
        else "auxiliary"
        if module_type == "auxiliary"
        else "other",
        module_type=module_type or None,
        description=text(row.get("description")),
        cves=refs,
        platforms=platforms,
        disclosure_date=text(row.get("disclosure_date"), 80) or None,
        modified_at=text(row.get("mod_time"), 80) or None,
        check_supported=row.get("check") if isinstance(row.get("check"), bool) else None,
        url=HttpUrl(
            f"https://github.com/rapid7/metasploit-framework/blob/master/{quote(path, safe='/')}"
        ),
    )


def nuclei_row(row: dict[str, Any]) -> PocResource | None:
    info = row.get("Info")
    if not isinstance(info, dict):
        raise ValueError("Invalid template metadata")
    classification = info.get("Classification") or {}
    if not isinstance(classification, dict):
        raise ValueError("Invalid classification")
    refs = cve_refs([row.get("ID")]) + cve_refs(classification.get("CVEID"))
    if not refs:
        return None
    path = safe_path(row.get("file_path"), source="nuclei")
    return PocResource(
        source="nuclei",
        id=path,
        path=path,
        name=text(info.get("Name"), 250) or path,
        kind="detection",
        description=text(info.get("Description")),
        cves=tuple(sorted(set(refs))),
        severity=text(info.get("Severity"), 40) or None,
        url=HttpUrl(
            "https://github.com/projectdiscovery/nuclei-templates/blob/main/"
            f"{quote(path, safe='/')}"
        ),
    )


def parse_index(source: Source, payload: bytes) -> MetadataIndex:
    if len(payload) > LIMITS[source]:
        raise ValueError("Metadata payload exceeded limit")
    rows: list[Any]
    skipped = 0
    if source == "metasploit":
        document = json.loads(payload)
        if not isinstance(document, dict) or not document:
            raise ValueError("Invalid module index")
        rows = list(document.values())
    else:
        rows = []
        for line in payload.decode("utf-8").splitlines():
            if line.strip():
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    skipped += 1
    if not rows or len(rows) > 20_000:
        raise ValueError("Invalid index size")
    records: dict[str, PocResource] = {}
    parser = metasploit_row if source == "metasploit" else nuclei_row
    for row in rows:
        try:
            if not isinstance(row, dict):
                raise ValueError("Invalid metadata row")
            record = parser(row)
            if record:
                old = records.get(record.id)
                if old:
                    record = record.model_copy(
                        update={"cves": tuple(sorted(set(old.cves + record.cves)))}
                    )
                records[record.id] = record
        except (ValueError, TypeError):
            skipped += 1
    if not records:
        raise ValueError("No usable CVE metadata")
    return MetadataIndex(tuple(sorted(records.values(), key=lambda item: item.id)), skipped)


async def download_index(source: Source) -> MetadataIndex:
    async with (
        httpx.AsyncClient(timeout=15, follow_redirects=False) as client,
        client.stream("GET", URLS[source]) as response,
    ):
        response.raise_for_status()
        if response.is_redirect:
            raise ValueError("Unexpected redirect")
        body = bytearray()
        async for chunk in response.aiter_bytes():
            body.extend(chunk)
            if len(body) > LIMITS[source]:
                raise ValueError("Metadata payload exceeded limit")
    return await asyncio.to_thread(parse_index, source, bytes(body))
