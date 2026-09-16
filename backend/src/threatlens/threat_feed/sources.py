"""Bounded RSS/JSON and metadata-only source adapters."""

from __future__ import annotations

import email.utils
import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import UTC, datetime

import httpx

from .logic import clean_text
from .models import SourceEntry

MAX_RESPONSE_BYTES = 2_000_000
MAX_ITEMS = 50


@dataclass(frozen=True)
class SourceDefinition:
    id: str
    name: str
    kind: str
    url: str


SOURCES: tuple[SourceDefinition, ...] = (
    SourceDefinition(
        "cisa_kev",
        "CISA KEV",
        "json",
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    ),
    SourceDefinition(
        "cisa",
        "CISA Advisories",
        "metadata",
        "https://www.cisa.gov/news-events/cybersecurity-advisories",
    ),
    SourceDefinition("mycert", "MyCERT", "metadata", "https://www.mycert.org.my/portal/advisories"),
    SourceDefinition(
        "nc4", "NACSA / NC4", "metadata", "https://www.nc4.gov.my/alertAdvisory?lang=en"
    ),
    SourceDefinition(
        "singcert",
        "Singapore CSA / SingCERT",
        "metadata",
        "https://www.csa.gov.sg/alerts-and-advisories/advisories/",
    ),
    SourceDefinition(
        "the_hacker_news", "The Hacker News", "rss", "https://feeds.feedburner.com/TheHackersNews"
    ),
    SourceDefinition(
        "bleepingcomputer", "BleepingComputer", "rss", "https://www.bleepingcomputer.com/feed/"
    ),
    SourceDefinition("talos", "Cisco Talos", "rss", "https://blog.talosintelligence.com/rss/"),
    SourceDefinition("unit42", "Unit 42", "rss", "https://unit42.paloaltonetworks.com/feed/"),
)


async def fetch_source(source: SourceDefinition) -> tuple[SourceEntry, ...]:
    async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
        response = await client.get(source.url, headers={"User-Agent": "ThreatLens/1.2 ThreatFeed"})
    response.raise_for_status()
    if len(response.content) > MAX_RESPONSE_BYTES:
        raise ValueError("source payload exceeded the safe size limit")
    if source.kind == "rss":
        return parse_rss(response.content)
    if source.kind == "json":
        return parse_kev(response.text)
    return parse_metadata_listing(response.text, source.url)


def _date(value: str | None) -> datetime:
    if value:
        try:
            parsed = email.utils.parsedate_to_datetime(value)
            return parsed.astimezone(UTC)
        except (TypeError, ValueError):
            try:
                return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)
            except ValueError:
                pass
    return datetime.now(UTC)


def parse_rss(payload: bytes) -> tuple[SourceEntry, ...]:
    root = ET.fromstring(payload)
    entries = root.findall(".//item") or root.findall(".//{http://www.w3.org/2005/Atom}entry")
    output: list[SourceEntry] = []
    for node in entries[:MAX_ITEMS]:

        def value(*names: str, node: ET.Element = node) -> str:
            for name in names:
                child = node.find(name)
                if child is not None and child.text:
                    return child.text.strip()
            return ""

        link = value("link", "{http://www.w3.org/2005/Atom}link")
        atom_link = node.find("{http://www.w3.org/2005/Atom}link")
        if atom_link is not None:
            link = atom_link.attrib.get("href", link)
        title = clean_text(value("title", "{http://www.w3.org/2005/Atom}title"), limit=500)
        if not title or not link:
            continue
        output.append(
            SourceEntry(
                guid=value("guid", "id", "{http://www.w3.org/2005/Atom}id") or None,
                title=title,
                excerpt=clean_text(
                    value("description", "summary", "{http://www.w3.org/2005/Atom}summary"),
                    limit=1200,
                ),
                url=link,
                published_at=_date(
                    value("pubDate", "published", "updated", "{http://www.w3.org/2005/Atom}updated")
                ),
                categories=tuple(
                    clean_text(item.text or "", limit=80) for item in node.findall("category")[:8]
                ),
            )
        )
    return tuple(output)


def parse_kev(payload: str) -> tuple[SourceEntry, ...]:
    data = json.loads(payload)
    output = []
    for row in data.get("vulnerabilities", [])[-MAX_ITEMS:]:
        cve = str(row.get("cveID", ""))
        title = f"{cve}: {row.get('vulnerabilityName', 'Known exploited vulnerability')}"
        output.append(
            SourceEntry(
                guid=cve,
                title=title,
                excerpt=clean_text(str(row.get("shortDescription", "")), limit=1200),
                url=f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext={cve}",
                published_at=_date(str(row.get("dateAdded", ""))),
                categories=("known exploited vulnerability",),
                severity="critical" if "critical" in title.lower() else None,
            )
        )
    return tuple(reversed(output))


def parse_metadata_listing(payload: str, base_url: str) -> tuple[SourceEntry, ...]:
    """Extract linked advisory metadata only; never fetch article bodies."""
    pattern = re.compile(
        r'<a[^>]+href=["\'](?P<href>[^"\']+)["\'][^>]*>(?P<title>.*?)</a>', re.I | re.S
    )
    output: list[SourceEntry] = []
    for match in pattern.finditer(payload):
        title = clean_text(match.group("title"), limit=500)
        if len(title) < 24 or not re.search(
            r"advis|alert|cyber|vulnerab|malware|ransom|phish|scam", title, re.I
        ):
            continue
        href = match.group("href")
        if href.startswith("/"):
            origin = re.match(r"https?://[^/]+", base_url)
            href = f"{origin.group(0) if origin else ''}{href}"
        if not href.startswith("http"):
            continue
        output.append(SourceEntry(title=title, url=href, published_at=datetime.now(UTC)))
        if len(output) >= MAX_ITEMS:
            break
    return tuple(output)
