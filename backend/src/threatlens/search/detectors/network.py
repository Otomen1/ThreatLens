"""Network-indicator detectors: URL, email, IPv4, IPv6, domain.

These use robust libraries rather than fragile regex: :mod:`ipaddress` for IPs
(which also rejects ambiguous forms like leading-zero octets), :mod:`urllib`
for URL structure, and the Public Suffix List (via :mod:`tldextract`) for
domains and email hosts.
"""

from __future__ import annotations

import ipaddress
import re
from typing import ClassVar
from urllib.parse import urlsplit, urlunsplit

from ...entities.types import EntityType
from ..tld import extract as tld_extract
from .base import DetectionContext, EntityDetector

_URL_SCHEMES = {"http", "https", "ftp", "ftps"}
_DEFAULT_PORTS = {"http": 80, "https": 443, "ftp": 21, "ftps": 990}

# Characters that disqualify a bare hostname (i.e. it is not just a domain).
_DOMAIN_FORBIDDEN = frozenset(" \t\r\n/\\@:?#[]()<>")

# Conservative local-part check; the hard part (the domain) is validated by PSL.
_EMAIL_LOCAL_RE = re.compile(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+")


def _parse_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def _valid_domain(value: str) -> bool:
    """True if ``value`` is a bare registrable domain (has a public suffix)."""
    if not value or any(c in _DOMAIN_FORBIDDEN for c in value):
        return False
    if _parse_ip(value) is not None:  # IPs are not domains
        return False
    ext = tld_extract(value)
    return bool(ext.domain and ext.suffix)


class UrlDetector(EntityDetector):
    entity_type: ClassVar[EntityType] = EntityType.URL
    priority: ClassVar[int] = 10

    def _parse(self, ctx: DetectionContext):
        s = ctx.normalized
        if "://" not in s:
            return None
        parts = urlsplit(s)
        if parts.scheme.lower() not in _URL_SCHEMES or not parts.hostname:
            return None
        return parts

    def matches(self, ctx: DetectionContext) -> bool:
        return self._parse(ctx) is not None

    def normalize(self, ctx: DetectionContext) -> str:
        parts = self._parse(ctx)
        assert parts is not None
        scheme = parts.scheme.lower()
        host = (parts.hostname or "").lower()
        netloc = host
        if parts.port is not None and parts.port != _DEFAULT_PORTS.get(scheme):
            netloc = f"{host}:{parts.port}"
        return urlunsplit((scheme, netloc, parts.path, parts.query, parts.fragment))


class EmailDetector(EntityDetector):
    entity_type: ClassVar[EntityType] = EntityType.EMAIL
    priority: ClassVar[int] = 20

    def _split(self, ctx: DetectionContext) -> tuple[str, str] | None:
        s = ctx.normalized
        if s.count("@") != 1:
            return None
        local, _, domain = s.partition("@")
        if not local or not _EMAIL_LOCAL_RE.fullmatch(local):
            return None
        if local.startswith(".") or local.endswith(".") or ".." in local:
            return None
        if not _valid_domain(domain):
            return None
        return local, domain

    def matches(self, ctx: DetectionContext) -> bool:
        return self._split(ctx) is not None

    def normalize(self, ctx: DetectionContext) -> str:
        parts = self._split(ctx)
        assert parts is not None
        local, domain = parts
        return f"{local}@{domain.lower()}"


class Ipv4Detector(EntityDetector):
    entity_type: ClassVar[EntityType] = EntityType.IPV4
    priority: ClassVar[int] = 30

    def matches(self, ctx: DetectionContext) -> bool:
        ip = _parse_ip(ctx.normalized)
        return ip is not None and ip.version == 4

    def normalize(self, ctx: DetectionContext) -> str:
        return str(ipaddress.IPv4Address(ctx.normalized))


class Ipv6Detector(EntityDetector):
    entity_type: ClassVar[EntityType] = EntityType.IPV6
    priority: ClassVar[int] = 40

    def matches(self, ctx: DetectionContext) -> bool:
        ip = _parse_ip(ctx.normalized)
        return ip is not None and ip.version == 6

    def normalize(self, ctx: DetectionContext) -> str:
        return str(ipaddress.IPv6Address(ctx.normalized))


class DomainDetector(EntityDetector):
    entity_type: ClassVar[EntityType] = EntityType.DOMAIN
    priority: ClassVar[int] = 90

    def matches(self, ctx: DetectionContext) -> bool:
        return _valid_domain(ctx.normalized.rstrip("."))

    def normalize(self, ctx: DetectionContext) -> str:
        return ctx.normalized.rstrip(".").lower()
