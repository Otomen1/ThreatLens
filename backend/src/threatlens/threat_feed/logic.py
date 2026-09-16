"""Deterministic normalization, classification, and summarization."""

from __future__ import annotations

import hashlib
import html
import re
from datetime import datetime
from urllib.parse import urlsplit, urlunsplit

from ..search import detect, extract_ioc_report
from .models import FeedEntity, FeedRegion, FeedTopic, SourceEntry

_TAG = re.compile(r"<[^>]+>")
_SPACE = re.compile(r"\s+")
_MALAYSIA = re.compile(
    r"\b(malaysia|malaysian|kuala lumpur|cyberjaya|mycert|nacsa|nc4|\.my\b)\b", re.I
)
_SEA = re.compile(
    r"\b(southeast asia|south-east asia|asean|singapore|indonesia|thailand|"
    r"philippines|vietnam|brunei|cambodia|laos|myanmar)\b",
    re.I,
)
_TOPICS: tuple[tuple[FeedTopic, tuple[str, ...]], ...] = (
    (FeedTopic.ACTIVE_EXPLOITATION, ("actively exploited", "active exploitation", "in the wild")),
    (FeedTopic.RANSOMWARE, ("ransomware",)),
    (FeedTopic.PHISHING, ("phishing", "credential theft")),
    (FeedTopic.SUPPLY_CHAIN, ("supply chain", "supply-chain")),
    (FeedTopic.BREACH, ("data breach", "breached", "intrusion")),
    (FeedTopic.SCAM, ("scam", "fraudulent", "fake website")),
    (FeedTopic.MALWARE, ("malware", "trojan", "backdoor", "botnet")),
    (FeedTopic.THREAT_ACTOR, ("threat actor", "apt", "state-sponsored")),
    (FeedTopic.VULNERABILITY, ("vulnerability", "cve-", "zero-day", "zero day")),
    (FeedTopic.ADVISORY, ("advisory", "alert")),
)


def clean_text(value: str, *, limit: int = 1200) -> str:
    text = html.unescape(_TAG.sub(" ", value))
    return _SPACE.sub(" ", text).strip()[:limit]


def canonical_url(value: str) -> str:
    parsed = urlsplit(value.strip())
    path = parsed.path.rstrip("/") or "/"
    return urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), path, "", ""))


def stable_id(source_id: str, entry: SourceEntry) -> str:
    basis = entry.guid or canonical_url(entry.url)
    if not basis:
        basis = f"{entry.title.lower()}|{entry.published_at.date().isoformat()}"
    return hashlib.sha256(f"{source_id}|{basis}".encode()).hexdigest()[:24]


def classify_topic(entry: SourceEntry) -> FeedTopic:
    material = f"{entry.title} {entry.excerpt} {' '.join(entry.categories)}".lower()
    for topic, keywords in _TOPICS:
        if any(keyword in material for keyword in keywords):
            return topic
    return FeedTopic.RESEARCH


def classify_region(source_id: str, entry: SourceEntry) -> tuple[FeedRegion, str, tuple[str, ...]]:
    material = f"{entry.title} {entry.excerpt} {' '.join(entry.categories)}"
    reasons: list[str] = []
    if source_id in {"mycert", "nc4"}:
        reasons.append("Published by an official Malaysian source")
    malaysia_matches = sorted({match.group(0) for match in _MALAYSIA.finditer(material)})
    if malaysia_matches:
        reasons.append(f"Mentions Malaysia signal: {malaysia_matches[0]}")
    if reasons:
        return (
            FeedRegion.MALAYSIA,
            "high" if source_id in {"mycert", "nc4"} else "medium",
            tuple(reasons),
        )
    if source_id == "singcert":
        reasons.append("Published by Singapore CSA/SingCERT")
    sea_matches = sorted({match.group(0) for match in _SEA.finditer(material)})
    if sea_matches:
        reasons.append(f"Mentions Southeast Asia signal: {sea_matches[0]}")
    if reasons:
        return (
            FeedRegion.SOUTHEAST_ASIA,
            "high" if source_id == "singcert" else "medium",
            tuple(reasons),
        )
    return FeedRegion.GLOBAL, "general", ("No specific Malaysia or Southeast Asia signal",)


def extract_entities(entry: SourceEntry) -> tuple[FeedEntity, ...]:
    material = clean_text(f"{entry.title}\n{entry.excerpt}", limit=6000)
    try:
        report = extract_ioc_report(material, detector=detect)
    except ValueError:
        return ()
    return tuple(
        FeedEntity(
            type=entity.type.value,
            value=entity.value,
            normalized_value=entity.normalized_value,
        )
        for entity in report.entities[:20]
    )


def deterministic_summary(entry: SourceEntry, topic: FeedTopic) -> str:
    excerpt = clean_text(entry.excerpt, limit=480)
    if excerpt:
        return excerpt
    return f"{clean_text(entry.title, limit=300)} Topic: {topic.value.replace('_', ' ')}."


def explicit_severity(entry: SourceEntry, topic: FeedTopic) -> str | None:
    supplied = (entry.severity or "").lower()
    if supplied in {"critical", "high", "medium", "low"}:
        return supplied
    material = f"{entry.title} {entry.excerpt}".lower()
    if topic is FeedTopic.ACTIVE_EXPLOITATION and "critical" in material:
        return "critical"
    return None


def within_retention(value: datetime, cutoff: datetime) -> bool:
    return value >= cutoff
