"""Deterministic normalization: raw repository record → :class:`CommunityRule`.

This is the heart of the library's "many repositories, one model" promise. Every
provider hands ``normalize_record`` a small raw record (upstream id, author, raw
rule text, and any structured metadata the repo publishes) and gets back a fully
populated, content-addressed :class:`CommunityRule`.

Pure and deterministic: MITRE techniques and IOCs are *extracted from the rule
text* with fixed regexes (so the parsing is real and testable), then unioned
with any structured hints the record carries. No network, no clock, no AI, no
fuzzy matching. The raw content is preserved verbatim and only ever withheld
when the license forbids redistribution.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable

from ..entities.types import EntityType
from .models import (
    CommunityRule,
    RuleAuthor,
    RuleIOC,
    RuleLicense,
    RuleReference,
    RuleSource,
    RuleVersion,
)
from .types import DetectionCategory, DetectionLanguage, DetectionSeverity, RulePlatform

# --------------------------------------------------------------------------- #
# Extraction regexes (deterministic, anchored, low false-positive)
# --------------------------------------------------------------------------- #

_TECHNIQUE_RE = re.compile(r"\bT(\d{4})(?:\.(\d{3}))?\b", re.IGNORECASE)
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_HASH_RE = re.compile(r"\b([a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\b")
_URL_RE = re.compile(r"https?://[^\s\"'<>)\]]+", re.IGNORECASE)
_DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b", re.IGNORECASE
)

# Trailing labels that mean a token is a filename, not a domain.
_FILE_EXTS = frozenset(
    [
        "exe",
        "dll",
        "sys",
        "ps1",
        "bat",
        "cmd",
        "vbs",
        "js",
        "jse",
        "py",
        "sh",
        "yml",
        "yaml",
        "json",
        "txt",
        "md",
        "rules",
        "dat",
        "bin",
        "docx",
        "xlsx",
        "lnk",
        "scr",
        "hta",
        "msi",
        "tmp",
        "log",
        "conf",
        "php",
        "aspx",
        "jsp",
        "htm",
        "html",
        "toml",
        "ini",
        "xml",
    ]
)

# A curated set of public suffixes: a bare ``a.b`` token is only treated as a
# domain when its last label is one of these. This rejects code identifiers and
# rule DSL tokens (``process.name``, ``dns.query``, ``attack.execution``) that
# would otherwise masquerade as domains.
_COMMON_TLDS = frozenset(
    [
        "com",
        "net",
        "org",
        "io",
        "ru",
        "cn",
        "uk",
        "de",
        "fr",
        "nl",
        "br",
        "jp",
        "kr",
        "su",
        "pw",
        "cc",
        "tk",
        "info",
        "biz",
        "xyz",
        "icu",
        "gov",
        "edu",
        "mil",
    ]
)

# Vendor / documentation hosts that appear in references but are never indicators.
_REFERENCE_DOMAINS = frozenset(
    [
        "mitre.org",
        "github.com",
        "elastic.co",
        "snort.org",
        "emergingthreats.net",
        "microsoft.com",
        "azure.com",
        "splunk.com",
        "spdx.org",
        "apache.org",
        "google.com",
        "githubusercontent.com",
        "virustotal.com",
    ]
)

_SEVERITY_WORDS = {
    "informational": DetectionSeverity.INFORMATIONAL,
    "info": DetectionSeverity.INFORMATIONAL,
    "low": DetectionSeverity.LOW,
    "medium": DetectionSeverity.MEDIUM,
    "high": DetectionSeverity.HIGH,
    "critical": DetectionSeverity.CRITICAL,
}

# Sigma logsource category / product → normalized detection category.
_CATEGORY_HINTS = {
    "process_creation": DetectionCategory.PROCESS,
    "registry_event": DetectionCategory.REGISTRY,
    "registry_set": DetectionCategory.REGISTRY,
    "registry_add": DetectionCategory.REGISTRY,
    "dns": DetectionCategory.DNS,
    "dns_query": DetectionCategory.DNS,
    "proxy": DetectionCategory.HTTP,
    "webserver": DetectionCategory.HTTP,
    "firewall": DetectionCategory.NETWORK,
    "network_connection": DetectionCategory.NETWORK,
}

_NETWORK_LANGUAGES = frozenset({DetectionLanguage.SURICATA, DetectionLanguage.SNORT})


def community_rule_id(source_id: str, rule_id: str, content_hash: str) -> str:
    """Content-addressed id: stable across syncs, unique per (source, rule, body)."""
    payload = f"{source_id.strip().lower()}|{rule_id.strip().lower()}|{content_hash}"
    return f"com_{hashlib.sha256(payload.encode('utf-8')).hexdigest()[:16]}"


def content_fingerprint(content: str) -> str:
    """A stable fingerprint of the rule body for versioning / change detection."""
    return hashlib.sha256(content.strip().encode("utf-8")).hexdigest()


def extract_mitre(content: str) -> tuple[str, ...]:
    """Extract ATT&CK technique ids (``T1059`` / ``T1059.001``), upper-cased & sorted."""
    found: set[str] = set()
    for base, sub in _TECHNIQUE_RE.findall(content):
        found.add(f"T{base}.{sub}" if sub else f"T{base}")
    return tuple(sorted(found))


def extract_iocs(content: str) -> tuple[RuleIOC, ...]:
    """Extract concrete indicators from rule text (deterministic, deduplicated).

    Recognises IPv4, MD5/SHA1/SHA256 hashes, URLs, and domains (bare domains and
    URL hosts, minus filenames). Order is stable: by type then value.
    """
    seen: set[tuple[EntityType, str]] = set()

    for raw in _IPV4_RE.findall(content):
        if _is_valid_ipv4(raw):
            seen.add((EntityType.IPV4, raw))

    for h in _HASH_RE.findall(content):
        etype = {32: EntityType.MD5, 40: EntityType.SHA1, 64: EntityType.SHA256}[len(h)]
        seen.add((etype, h.lower()))

    for url in _URL_RE.findall(content):
        cleaned = url.rstrip(".,;\"')")
        host = re.sub(r"^https?://", "", cleaned, flags=re.IGNORECASE).split("/")[0].lower()
        if not _is_reference_host(host):
            seen.add((EntityType.URL, cleaned))

    for dom in _DOMAIN_RE.findall(content):
        lowered = dom.lower()
        if _looks_like_domain(lowered) and not _is_reference_host(lowered):
            seen.add((EntityType.DOMAIN, lowered))

    ordered = sorted(seen, key=lambda pair: (pair[0].value, pair[1]))
    return tuple(RuleIOC(type=etype, value=value) for etype, value in ordered)


def infer_severity(content: str, declared: str | None) -> DetectionSeverity:
    """Sigma ``level:`` → severity; else the declared word; else MEDIUM."""
    match = re.search(r"^\s*level:\s*([a-zA-Z]+)", content, re.MULTILINE)
    if match:
        word = match.group(1).lower()
        if word in _SEVERITY_WORDS:
            return _SEVERITY_WORDS[word]
    if declared and declared.lower() in _SEVERITY_WORDS:
        return _SEVERITY_WORDS[declared.lower()]
    return DetectionSeverity.MEDIUM


def infer_category(language: DetectionLanguage, content: str) -> DetectionCategory:
    """Normalized telemetry category from language + Sigma logsource hints."""
    if language in _NETWORK_LANGUAGES:
        return DetectionCategory.NETWORK
    if language is DetectionLanguage.YARA:
        return DetectionCategory.FILE
    lowered = content.lower()
    for token, category in _CATEGORY_HINTS.items():
        if token in lowered:
            return category
    if language is DetectionLanguage.SIGMA:
        return DetectionCategory.HOST
    return DetectionCategory.GENERIC


def infer_platforms(
    language: DetectionLanguage, content: str, declared: Iterable[str]
) -> tuple[RulePlatform, ...]:
    """Platforms from declared hints + language + Sigma ``product:`` lines."""
    platforms: set[RulePlatform] = set()
    for name in declared:
        try:
            platforms.add(RulePlatform(name.strip().lower()))
        except ValueError:
            continue
    if language in _NETWORK_LANGUAGES:
        platforms.add(RulePlatform.NETWORK)
    lowered = content.lower()
    for product, platform in (
        ("product: windows", RulePlatform.WINDOWS),
        ("product: linux", RulePlatform.LINUX),
        ("product: macos", RulePlatform.MACOS),
        ("product: aws", RulePlatform.CLOUD),
        ("product: azure", RulePlatform.CLOUD),
        ("product: gcp", RulePlatform.CLOUD),
    ):
        if product in lowered:
            platforms.add(platform)
    if not platforms:
        platforms.add(RulePlatform.GENERIC)
    return tuple(sorted(platforms, key=lambda p: p.value))


def normalize_record(source: RuleSource, record: dict[str, object]) -> CommunityRule:
    """Map one raw provider record into a canonical :class:`CommunityRule`.

    ``record`` carries the upstream id, name, author, raw content, and any
    structured metadata the repository publishes (tags/actors/malware/platforms).
    Techniques and IOCs are re-extracted from the content and unioned with the
    structured hints; nothing here reaches the network or the clock.
    """
    content = str(record.get("content", "")).rstrip() + "\n"
    rule_id = str(record["rule_id"])
    fingerprint = content_fingerprint(content)

    language = _coerce_language(record.get("language"), source)
    declared_platforms = _as_str_tuple(record.get("platforms"))

    techniques = _union(extract_mitre(content), _as_str_tuple(record.get("mitre")))
    tags = tuple(sorted({t.lower() for t in _as_str_tuple(record.get("tags"))}))
    actors = _union((), _as_str_tuple(record.get("actors")))
    malware = _union((), _as_str_tuple(record.get("malware")))

    license_ = _coerce_license(record.get("license"), source)
    redistributable = license_.redistributable

    references = tuple(
        RuleReference(title=_reference_title(url), url=url)
        for url in _as_str_tuple(record.get("references"))
    )

    return CommunityRule(
        id=community_rule_id(source.id, rule_id, fingerprint),
        source=source,
        rule_id=rule_id,
        name=str(record.get("name") or rule_id),
        language=language,
        category=infer_category(language, content),
        severity=infer_severity(content, _opt_str(record.get("severity"))),
        description=str(record.get("description", "")),
        author=_coerce_author(record.get("author")),
        license=license_,
        version=RuleVersion(
            version=str(record.get("version", "1")),
            revision=_as_int(record.get("revision"), 1),
            content_hash=fingerprint,
            updated=_opt_str(record.get("updated")),
        ),
        url=str(record.get("url") or source.url),
        path=str(record.get("path", "")),
        tags=tags,
        mitre_techniques=techniques,
        threat_actors=actors,
        malware_families=malware,
        platforms=infer_platforms(language, content, declared_platforms),
        iocs=extract_iocs(content),
        references=references,
        content=content if redistributable else None,
    )


# --------------------------------------------------------------------------- #
# Small pure helpers
# --------------------------------------------------------------------------- #


def _is_valid_ipv4(value: str) -> bool:
    parts = value.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def _looks_like_domain(token: str) -> bool:
    labels = token.split(".")
    if len(labels) < 2 or labels[-1] in _FILE_EXTS:
        return False
    return labels[-1] in _COMMON_TLDS  # curated public suffix → not a code token


def _is_reference_host(host: str) -> bool:
    """True if ``host`` is (or is a subdomain of) a known vendor/reference domain."""
    return any(host == ref or host.endswith("." + ref) for ref in _REFERENCE_DOMAINS)


def _coerce_language(value: object, source: RuleSource) -> DetectionLanguage:
    if isinstance(value, str):
        try:
            return DetectionLanguage(value)
        except ValueError:
            pass
    return source.languages[0] if source.languages else DetectionLanguage.GENERIC


def _coerce_license(value: object, source: RuleSource) -> RuleLicense:
    return value if isinstance(value, RuleLicense) else source.license


def _coerce_author(value: object) -> RuleAuthor:
    if isinstance(value, RuleAuthor):
        return value
    if isinstance(value, str) and value.strip():
        return RuleAuthor(name=value.strip())
    return RuleAuthor(name="Unknown")


def _as_str_tuple(value: object) -> tuple[str, ...]:
    if isinstance(value, (list, tuple)):
        return tuple(str(v) for v in value if str(v).strip())
    if isinstance(value, str) and value.strip():
        return (value.strip(),)
    return ()


def _opt_str(value: object) -> str | None:
    return str(value) if value not in (None, "") else None


def _as_int(value: object, default: int) -> int:
    if isinstance(value, bool):
        return default
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value)
    return default


def _union(a: tuple[str, ...], b: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(sorted(set(a) | set(b)))


def _reference_title(url: str) -> str:
    host = re.sub(r"^https?://", "", url).split("/")[0]
    return host or url
