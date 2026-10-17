"""Bounded RSS/JSON and metadata-only source adapters."""

from __future__ import annotations

import asyncio
import email.utils
import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, timezone, tzinfo
from urllib.parse import urlsplit

import httpx

from ..release import release_version
from .listing import parse_listing
from .logic import clean_text
from .models import FeedSourceOption, SourceEntry

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
        "rss",
        "https://cisa.gov/cybersecurity-advisories/all.xml",
    ),
    SourceDefinition("mycert", "MyCERT", "rss", "https://www.mycert.org.my/portal/rss"),
    SourceDefinition(
        "nc4", "NACSA / NC4", "metadata", "https://www.nc4.gov.my/alertAdvisory?lang=en"
    ),
    SourceDefinition(
        "singcert",
        "Singapore CSA / SingCERT",
        "rss",
        "https://www.csa.gov.sg/alerts-and-advisories/advisories/rss.xml",
    ),
    SourceDefinition(
        "the_hacker_news", "The Hacker News", "rss", "https://feeds.feedburner.com/TheHackersNews"
    ),
    SourceDefinition(
        "bleepingcomputer", "BleepingComputer", "rss", "https://www.bleepingcomputer.com/feed/"
    ),
    SourceDefinition("talos", "Cisco Talos", "rss", "https://blog.talosintelligence.com/rss/"),
    SourceDefinition("unit42", "Unit 42", "rss", "https://unit42.paloaltonetworks.com/feed/"),
    SourceDefinition("ahnlab", "AhnLab ASEC", "rss", "https://asec.ahnlab.com/en/feed/"),
    SourceDefinition(
        "fortinet",
        "Fortinet FortiGuard Labs",
        "rss",
        "https://feeds.fortinet.com/fortinet/blog/threat-research",
    ),
    SourceDefinition(
        "eset", "ESET WeLiveSecurity", "rss", "https://www.welivesecurity.com/en/rss/feed/"
    ),
)


SOURCE_OPTIONS = tuple(FeedSourceOption(id=source.id, name=source.name) for source in SOURCES)


async def fetch_source(source: SourceDefinition) -> tuple[SourceEntry, ...]:
    headers = {"Accept": "application/rss+xml, application/xml;q=0.9, */*;q=0.1"}
    if source.id != "cisa":
        headers["User-Agent"] = f"ThreatLens/{release_version()} ThreatFeed"
    # CISA's feed accepts the HTTP library's normal agent but rejects the custom agent.
    # Do not spoof a browser, retry a 403, or fetch article bodies as a workaround.
    async with (
        asyncio.timeout(25),
        httpx.AsyncClient(timeout=httpx.Timeout(20, connect=10), follow_redirects=True) as client,
        client.stream("GET", source.url, headers=headers) as response,
    ):
        response.raise_for_status()
        body = bytearray()
        async for chunk in response.aiter_bytes():
            body.extend(chunk)
            if len(body) > MAX_RESPONSE_BYTES:
                raise ValueError("source payload exceeded the safe size limit")
    payload = bytes(body)
    if source.kind == "rss":
        entries = parse_rss(payload, source_id=source.id)
    elif source.kind == "json":
        entries = parse_kev(payload.decode("utf-8-sig"))
    else:
        entries = parse_metadata_listing(payload.decode("utf-8"), source.url)
    if not entries:
        raise ValueError("source returned no dated report metadata")
    return entries


def _date(value: str | None, default_tz: tzinfo = UTC) -> datetime | None:
    if not value:
        return None
    # The permissive email parser ignores AM/PM in MyCERT's human-readable dates.
    for pattern in ("%d %B %Y, %I:%M %p", "%d %b %Y", "%d %B %Y"):
        try:
            return datetime.strptime(value, pattern).replace(tzinfo=default_tz).astimezone(UTC)
        except ValueError:
            continue
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        try:
            parsed = email.utils.parsedate_to_datetime(value)
        except (TypeError, ValueError, OverflowError):
            return None
    return (parsed if parsed.tzinfo else parsed.replace(tzinfo=default_tz)).astimezone(UTC)


def parse_rss(payload: bytes, *, source_id: str = "") -> tuple[SourceEntry, ...]:
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
        original = value("{http://rssnamespace.org/feedburner/ext/1.0}origLink")
        if original:
            try:
                parsed = urlsplit(original)
                if (
                    parsed.scheme in {"https", "http"}
                    and parsed.hostname
                    and not parsed.username
                    and not parsed.password
                ):
                    link = original
            except ValueError:
                pass
        title = clean_text(value("title", "{http://www.w3.org/2005/Atom}title"), limit=500)
        if not title or not link:
            continue
        excerpt = clean_text(
            value("description", "summary", "{http://www.w3.org/2005/Atom}summary"), limit=1200
        )
        published = _date(
            value(
                "pubDate",
                "published",
                "{http://www.w3.org/2005/Atom}published",
                "updated",
                "{http://www.w3.org/2005/Atom}updated",
                "{http://purl.org/dc/elements/1.1/}date",
            )
        )
        if published is None and source_id == "mycert":
            match = re.fullmatch(r"Published date:\s*(.+)", excerpt, re.I)
            if match:
                published = _date(match[1], timezone(timedelta(hours=8)))
                excerpt = ""
        if published is None:
            continue
        output.append(
            SourceEntry(
                guid=value("guid", "id", "{http://www.w3.org/2005/Atom}id") or None,
                title=title,
                excerpt=excerpt,
                url=link,
                published_at=published,
                categories=tuple(
                    clean_text(item.text or "", limit=80) for item in node.findall("category")[:8]
                ),
            )
        )
    return tuple(output)


def parse_kev(payload: str) -> tuple[SourceEntry, ...]:
    data = json.loads(payload)
    output = []
    rows = sorted(
        data.get("vulnerabilities", []),
        key=lambda row: str(row.get("dateAdded", "")),
        reverse=True,
    )
    for row in rows[:MAX_ITEMS]:
        cve = str(row.get("cveID", ""))
        published = _date(str(row.get("dateAdded", "")))
        if published is None or not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve):
            continue
        title = f"{cve}: {row.get('vulnerabilityName', 'Known exploited vulnerability')}"
        output.append(
            SourceEntry(
                guid=cve,
                title=title,
                excerpt=clean_text(str(row.get("shortDescription", "")), limit=1200),
                url=f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext={cve}",
                published_at=published,
                categories=("known exploited vulnerability",),
                severity="critical" if "critical" in title.lower() else None,
                vendor=clean_text(str(row.get("vendorProject", "")), limit=150) or None,
                product=clean_text(str(row.get("product", "")), limit=150) or None,
                known_exploited=True,
            )
        )
    return tuple(output)


def parse_metadata_listing(payload: str, base_url: str) -> tuple[SourceEntry, ...]:
    """Read dated NC4 listing cards, not navigation or full article pages."""
    return parse_listing(payload, base_url, limit=MAX_ITEMS)
