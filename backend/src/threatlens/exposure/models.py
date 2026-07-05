"""Canonical models for the Exposure Intelligence Framework (Phase 5.0).

Mirrors ``providers/models.py`` and ``providers/results.py``: closed
vocabularies plus frozen Pydantic value objects. Exposure Intelligence answers
"where is this entity exposed" (open ports, certificates, passive DNS,
hosting, subdomains, breaches, paste sites, …) — it is purely descriptive and
carries no reputation, no severity, and no malicious/benign verdict. That
question belongs to Threat Intelligence (``providers/``), a separate
framework this package never imports from.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, JsonValue

from ..entities.types import EntityType

# --------------------------------------------------------------------------- #
# Vocabularies
# --------------------------------------------------------------------------- #


class ExposureCapability(StrEnum):
    """A kind of exposure fact a provider can report.

    Doubles as both a provider's declared capability (for routing) and a
    finding's category — there is no live data yet to justify two separate
    taxonomies (see ``providers/types.py::ProviderCapability`` for the
    equivalent single-enum choice in the Threat Intelligence framework).
    """

    OPEN_PORTS = "open_ports"
    CERTIFICATES = "certificates"
    PASSIVE_DNS = "passive_dns"
    HOSTING = "hosting"
    ASN = "asn"
    SERVICES = "services"
    SUBDOMAINS = "subdomains"
    DNS_HISTORY = "dns_history"
    BREACHES = "breaches"
    CREDENTIAL_EXPOSURE = "credential_exposure"
    PASTES = "pastes"


class ExposureAuthType(StrEnum):
    """How a provider authenticates. Metadata only — no auth is performed here."""

    NONE = "none"
    API_KEY = "api_key"
    OAUTH2 = "oauth2"
    BASIC = "basic"


class ExposureProviderStatus(StrEnum):
    """Coarse operational state reported by ``ExposureProvider.health``."""

    UNKNOWN = "unknown"
    OPERATIONAL = "operational"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"
    DISABLED = "disabled"


class ExposureStatus(StrEnum):
    """Outcome of a single provider lookup (mirrors ``providers.ResultStatus``)."""

    OK = "ok"
    NOT_FOUND = "not_found"
    UNSUPPORTED = "unsupported"
    ERROR = "error"
    TIMEOUT = "timeout"
    RATE_LIMITED = "rate_limited"
    UNAUTHORIZED = "unauthorized"


_HARD_ERRORS = frozenset(
    {
        ExposureStatus.ERROR,
        ExposureStatus.TIMEOUT,
        ExposureStatus.RATE_LIMITED,
        ExposureStatus.UNAUTHORIZED,
    }
)


# --------------------------------------------------------------------------- #
# Provider description
# --------------------------------------------------------------------------- #


class ExposureProviderMetadata(BaseModel):
    """Static description of an exposure provider.

    The contract the registry indexes and routes against — a provider is
    fully described by this object plus its (later) ``lookup`` implementation.
    """

    model_config = ConfigDict(frozen=True)

    name: str = Field(min_length=1)  # machine identifier, e.g. "shodan"
    display_name: str = Field(min_length=1)  # human label, e.g. "Shodan"
    supported_entity_types: frozenset[EntityType] = Field(min_length=1)
    capabilities: frozenset[ExposureCapability] = Field(default_factory=frozenset)
    priority: int = 100  # lower runs first, matching the provider registry convention
    auth_type: ExposureAuthType = ExposureAuthType.API_KEY
    enabled: bool = True

    @property
    def requires_auth(self) -> bool:
        """Whether the provider needs credentials to operate."""
        return self.auth_type is not ExposureAuthType.NONE


class ExposureProviderHealth(BaseModel):
    """A point-in-time health snapshot for one exposure provider."""

    model_config = ConfigDict(frozen=True)

    name: str
    status: ExposureProviderStatus
    detail: str | None = None


# --------------------------------------------------------------------------- #
# Components
# --------------------------------------------------------------------------- #


class ExposureEvidence(BaseModel):
    """A single structured, descriptive observation supporting a finding.

    Never a verdict — a fact ("port 22 is open", "certificate issued by
    Let's Encrypt on 2024-01-01"), typed as data rather than prose.
    """

    model_config = ConfigDict(frozen=True)

    type: str = Field(min_length=1)
    summary: str = Field(min_length=1)
    value: str | None = None
    observed_at: datetime | None = None
    data: dict[str, JsonValue] = Field(default_factory=dict)


class ExposureAsset(BaseModel):
    """A discovered asset tied to the subject entity (a port, host, subdomain, …)."""

    model_config = ConfigDict(frozen=True)

    asset_type: str = Field(min_length=1)  # e.g. "open_port", "subdomain", "certificate"
    value: str = Field(min_length=1)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    attributes: dict[str, JsonValue] = Field(default_factory=dict)


class ExposureReference(BaseModel):
    """An external citation backing a finding (a link to a source page)."""

    model_config = ConfigDict(frozen=True)

    title: str = Field(min_length=1)
    url: str = Field(min_length=1)
    description: str | None = None


class ExposureFindingError(BaseModel):
    """Why a provider lookup failed (or partially failed)."""

    model_config = ConfigDict(frozen=True)

    message: str = Field(min_length=1)
    retryable: bool = False
    detail: str | None = None


class ExposureFinding(BaseModel):
    """One provider's descriptive finding about an entity's exposure.

    A failed lookup is still a valid finding (status + error), so aggregation
    can proceed when some providers succeed and others fail — mirrors
    ``providers.IntelligenceResult``.
    """

    model_config = ConfigDict(frozen=True)

    provider: str = Field(min_length=1)
    provider_display_name: str | None = None
    entity_type: EntityType
    entity_value: str = Field(min_length=1)

    status: ExposureStatus = ExposureStatus.OK
    error: ExposureFindingError | None = None

    category: ExposureCapability | None = None
    summary: str = ""
    evidence: list[ExposureEvidence] = Field(default_factory=list)
    assets: list[ExposureAsset] = Field(default_factory=list)
    references: list[ExposureReference] = Field(default_factory=list)

    fetched_at: datetime | None = None

    @property
    def is_ok(self) -> bool:
        return self.status is ExposureStatus.OK

    @property
    def is_error(self) -> bool:
        return self.status in _HARD_ERRORS

    @property
    def has_findings(self) -> bool:
        return bool(self.evidence or self.assets)

    @classmethod
    def not_found(
        cls,
        *,
        provider: str,
        entity_type: EntityType,
        entity_value: str,
        provider_display_name: str | None = None,
    ) -> ExposureFinding:
        """Build a finding for an entity the provider has no data on."""
        return cls(
            provider=provider,
            provider_display_name=provider_display_name,
            entity_type=entity_type,
            entity_value=entity_value,
            status=ExposureStatus.NOT_FOUND,
        )

    @classmethod
    def unsupported(
        cls,
        *,
        provider: str,
        entity_type: EntityType,
        entity_value: str,
        provider_display_name: str | None = None,
    ) -> ExposureFinding:
        """Build a finding for an entity type the provider does not handle."""
        return cls(
            provider=provider,
            provider_display_name=provider_display_name,
            entity_type=entity_type,
            entity_value=entity_value,
            status=ExposureStatus.UNSUPPORTED,
        )

    @classmethod
    def failure(
        cls,
        *,
        provider: str,
        entity_type: EntityType,
        entity_value: str,
        message: str,
        status: ExposureStatus = ExposureStatus.ERROR,
        retryable: bool = False,
        detail: str | None = None,
        provider_display_name: str | None = None,
    ) -> ExposureFinding:
        """Build a failed finding. ``status`` must be an error-ish state."""
        return cls(
            provider=provider,
            provider_display_name=provider_display_name,
            entity_type=entity_type,
            entity_value=entity_value,
            status=status,
            error=ExposureFindingError(message=message, retryable=retryable, detail=detail),
        )


# --------------------------------------------------------------------------- #
# Summary (the canonical output)
# --------------------------------------------------------------------------- #


class ExposureMetadata(BaseModel):
    """Provenance for an :class:`ExposureSummary`."""

    model_config = ConfigDict(frozen=True)

    entity_type: EntityType
    entity_value: str
    generated_at: datetime
    framework_version: str


class ExposureStatistics(BaseModel):
    """Aggregate counts over an :class:`ExposureSummary`'s findings."""

    model_config = ConfigDict(frozen=True)

    providers_queried: int = Field(default=0, ge=0)
    providers_ok: int = Field(default=0, ge=0)
    total_findings: int = Field(default=0, ge=0)
    total_assets: int = Field(default=0, ge=0)
    categories: frozenset[ExposureCapability] = frozenset()


class ExposureSummary(BaseModel):
    """Every provider's exposure findings about one entity, merged.

    The canonical output of :class:`~threatlens.exposure.service.ExposureService`.
    With zero providers registered (Phase 5.0), every summary is empty by
    construction — the real aggregation path, not a special-cased stub;
    future providers populate it without changing this contract.
    """

    model_config = ConfigDict(frozen=True)

    entity_type: EntityType
    entity_value: str
    findings: list[ExposureFinding] = Field(default_factory=list)
    references: list[ExposureReference] = Field(default_factory=list)
    statistics: ExposureStatistics
    metadata: ExposureMetadata

    @property
    def has_findings(self) -> bool:
        return bool(self.findings)
