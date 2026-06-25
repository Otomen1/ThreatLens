"""Closed vocabularies describing intelligence providers.

Mirrors the style of ``entities/types.py``: ``StrEnum`` values that are stable
string identifiers safe to persist and expose over the API. These describe *what
a provider is and can do* — they carry no behavior and trigger no network calls.
"""

from __future__ import annotations

from enum import StrEnum


class ProviderCapability(StrEnum):
    """A kind of enrichment a provider can perform for an entity.

    Routing can narrow to a single capability (e.g. "which providers give a
    reputation for this IP?") rather than fanning out to every capable provider.
    """

    REPUTATION = "reputation"
    MALWARE_ANALYSIS = "malware_analysis"
    PASSIVE_DNS = "passive_dns"
    WHOIS = "whois"
    GEOLOCATION = "geolocation"
    URL_ANALYSIS = "url_analysis"
    BLOCKLIST = "blocklist"
    SAMPLE_RETRIEVAL = "sample_retrieval"
    THREAT_CONTEXT = "threat_context"


class ProviderAuthType(StrEnum):
    """How a provider authenticates. Metadata only — no auth is performed here."""

    NONE = "none"
    API_KEY = "api_key"
    OAUTH2 = "oauth2"
    BASIC = "basic"


class ProviderStatus(StrEnum):
    """Coarse operational state reported by ``IntelligenceProvider.health``."""

    UNKNOWN = "unknown"
    OPERATIONAL = "operational"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"
    DISABLED = "disabled"
