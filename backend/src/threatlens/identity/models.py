"""Canonical models for the Identity Intelligence Framework (Phase 6.0).

Mirrors ``exposure/models.py`` (which itself mirrors ``providers/models.py``):
closed vocabularies plus frozen Pydantic value objects. Identity Intelligence
answers "what is known about this identity" (breach appearances, credential
exposure, paste-site history, linked accounts, directory profile, group
membership, MFA state, sign-in activity, …) — it is purely descriptive and
carries no reputation, no severity, and no compromised/safe verdict.

Whether an identity is *malicious* is Threat Intelligence's question
(``providers/``); whether a host is *exposed* is Exposure Intelligence's
(``exposure/``). Identity Intelligence is a third, separate framework this
package never imports from and that never imports from here. Where a future
provider reports a first-party risk signal (e.g. an IdP's own "risky user"
flag), that is reported as a quoted, attributed *third-party* fact inside an
:class:`IdentityEvidence`, never a ThreatLens-computed verdict — the same
discipline ``exposure`` already applies to GreyNoise's classification.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, JsonValue

from ..entities.types import EntityType

# --------------------------------------------------------------------------- #
# Vocabularies
# --------------------------------------------------------------------------- #


class IdentityCapability(StrEnum):
    """A kind of identity fact a provider can report.

    Doubles as both a provider's declared capability (for routing) and a
    finding's category — there is no live data yet to justify two separate
    taxonomies (see ``exposure/models.py::ExposureCapability`` and
    ``providers/types.py::ProviderCapability`` for the same single-enum choice
    in the sibling frameworks). Spans both breach-intelligence providers
    (HIBP-style) and directory/IdP providers (Entra/Okta/AD-style), so a
    future provider of either kind fits without a vocabulary change.
    """

    BREACHES = "breaches"
    CREDENTIAL_EXPOSURE = "credential_exposure"
    PASTES = "pastes"
    LINKED_ACCOUNTS = "linked_accounts"
    DIRECTORY_PROFILE = "directory_profile"
    GROUP_MEMBERSHIP = "group_membership"
    ROLE_ASSIGNMENTS = "role_assignments"
    MFA_STATUS = "mfa_status"
    AUTHENTICATION_ACTIVITY = "authentication_activity"
    RISK_SIGNALS = "risk_signals"


class IdentityAuthType(StrEnum):
    """How a provider authenticates. Metadata only — no auth is performed here."""

    NONE = "none"
    API_KEY = "api_key"
    OAUTH2 = "oauth2"
    BASIC = "basic"


class IdentityProviderStatus(StrEnum):
    """Coarse operational state reported by ``IdentityProvider.health``."""

    UNKNOWN = "unknown"
    OPERATIONAL = "operational"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"
    DISABLED = "disabled"


class IdentityStatus(StrEnum):
    """Outcome of a single provider lookup (mirrors ``exposure.ExposureStatus``)."""

    OK = "ok"
    NOT_FOUND = "not_found"
    UNSUPPORTED = "unsupported"
    ERROR = "error"
    TIMEOUT = "timeout"
    RATE_LIMITED = "rate_limited"
    UNAUTHORIZED = "unauthorized"


_HARD_ERRORS = frozenset(
    {
        IdentityStatus.ERROR,
        IdentityStatus.TIMEOUT,
        IdentityStatus.RATE_LIMITED,
        IdentityStatus.UNAUTHORIZED,
    }
)


# --------------------------------------------------------------------------- #
# Provider description
# --------------------------------------------------------------------------- #


class IdentityProviderMetadata(BaseModel):
    """Static description of an identity provider.

    The contract the registry indexes and routes against — a provider is
    fully described by this object plus its (later) ``lookup`` implementation.
    """

    model_config = ConfigDict(frozen=True)

    name: str = Field(min_length=1)  # machine identifier, e.g. "hibp"
    display_name: str = Field(min_length=1)  # human label, e.g. "Have I Been Pwned"
    supported_entity_types: frozenset[EntityType] = Field(min_length=1)
    capabilities: frozenset[IdentityCapability] = Field(default_factory=frozenset)
    priority: int = 100  # lower runs first, matching the provider registry convention
    auth_type: IdentityAuthType = IdentityAuthType.API_KEY
    enabled: bool = True

    @property
    def requires_auth(self) -> bool:
        """Whether the provider needs credentials to operate."""
        return self.auth_type is not IdentityAuthType.NONE


class IdentityProviderHealth(BaseModel):
    """A point-in-time health snapshot for one identity provider."""

    model_config = ConfigDict(frozen=True)

    name: str
    status: IdentityProviderStatus
    detail: str | None = None


# --------------------------------------------------------------------------- #
# Components
# --------------------------------------------------------------------------- #


class IdentityEvidence(BaseModel):
    """A single structured, descriptive observation supporting a finding.

    Never a verdict — a fact ("appears in the 2019 Collection #1 breach",
    "MFA enrolled: true", "last interactive sign-in 2024-01-01"), typed as
    data rather than prose.
    """

    model_config = ConfigDict(frozen=True)

    type: str = Field(min_length=1)
    summary: str = Field(min_length=1)
    value: str | None = None
    observed_at: datetime | None = None
    data: dict[str, JsonValue] = Field(default_factory=dict)


class IdentityAsset(BaseModel):
    """A discovered artifact tied to the subject identity.

    e.g. a breached account, a leaked credential record, a linked account on
    another service, a directory account object.
    """

    model_config = ConfigDict(frozen=True)

    asset_type: str = Field(min_length=1)  # e.g. "breached_account", "linked_account"
    value: str = Field(min_length=1)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    attributes: dict[str, JsonValue] = Field(default_factory=dict)


class IdentityReference(BaseModel):
    """An external citation backing a finding (a link to a source page)."""

    model_config = ConfigDict(frozen=True)

    title: str = Field(min_length=1)
    url: str = Field(min_length=1)
    description: str | None = None


class IdentityFindingError(BaseModel):
    """Why a provider lookup failed (or partially failed)."""

    model_config = ConfigDict(frozen=True)

    message: str = Field(min_length=1)
    retryable: bool = False
    detail: str | None = None


class IdentityFinding(BaseModel):
    """One provider's descriptive finding about an identity.

    A failed lookup is still a valid finding (status + error), so aggregation
    can proceed when some providers succeed and others fail — mirrors
    ``exposure.ExposureFinding`` / ``providers.IntelligenceResult``.
    """

    model_config = ConfigDict(frozen=True)

    provider: str = Field(min_length=1)
    provider_display_name: str | None = None
    entity_type: EntityType
    entity_value: str = Field(min_length=1)

    status: IdentityStatus = IdentityStatus.OK
    error: IdentityFindingError | None = None

    category: IdentityCapability | None = None
    summary: str = ""
    evidence: list[IdentityEvidence] = Field(default_factory=list)
    assets: list[IdentityAsset] = Field(default_factory=list)
    references: list[IdentityReference] = Field(default_factory=list)

    fetched_at: datetime | None = None

    @property
    def is_ok(self) -> bool:
        return self.status is IdentityStatus.OK

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
    ) -> IdentityFinding:
        """Build a finding for an identity the provider has no data on."""
        return cls(
            provider=provider,
            provider_display_name=provider_display_name,
            entity_type=entity_type,
            entity_value=entity_value,
            status=IdentityStatus.NOT_FOUND,
        )

    @classmethod
    def unsupported(
        cls,
        *,
        provider: str,
        entity_type: EntityType,
        entity_value: str,
        provider_display_name: str | None = None,
    ) -> IdentityFinding:
        """Build a finding for an entity type the provider does not handle."""
        return cls(
            provider=provider,
            provider_display_name=provider_display_name,
            entity_type=entity_type,
            entity_value=entity_value,
            status=IdentityStatus.UNSUPPORTED,
        )

    @classmethod
    def failure(
        cls,
        *,
        provider: str,
        entity_type: EntityType,
        entity_value: str,
        message: str,
        status: IdentityStatus = IdentityStatus.ERROR,
        retryable: bool = False,
        detail: str | None = None,
        provider_display_name: str | None = None,
    ) -> IdentityFinding:
        """Build a failed finding. ``status`` must be an error-ish state."""
        return cls(
            provider=provider,
            provider_display_name=provider_display_name,
            entity_type=entity_type,
            entity_value=entity_value,
            status=status,
            error=IdentityFindingError(message=message, retryable=retryable, detail=detail),
        )


# --------------------------------------------------------------------------- #
# Summary (the canonical output)
# --------------------------------------------------------------------------- #


class IdentityMetadata(BaseModel):
    """Provenance for an :class:`IdentitySummary`."""

    model_config = ConfigDict(frozen=True)

    entity_type: EntityType
    entity_value: str
    generated_at: datetime
    framework_version: str


class IdentityStatistics(BaseModel):
    """Aggregate counts over an :class:`IdentitySummary`'s findings."""

    model_config = ConfigDict(frozen=True)

    providers_queried: int = Field(default=0, ge=0)
    providers_ok: int = Field(default=0, ge=0)
    total_findings: int = Field(default=0, ge=0)
    total_assets: int = Field(default=0, ge=0)
    categories: frozenset[IdentityCapability] = frozenset()


class IdentitySummary(BaseModel):
    """Every provider's identity findings about one entity, merged.

    The canonical output of :class:`~threatlens.identity.service.IdentityService`.
    With zero providers registered (Phase 6.0), every summary is empty by
    construction — the real aggregation path, not a special-cased stub;
    future providers populate it without changing this contract.
    """

    model_config = ConfigDict(frozen=True)

    entity_type: EntityType
    entity_value: str
    findings: list[IdentityFinding] = Field(default_factory=list)
    references: list[IdentityReference] = Field(default_factory=list)
    statistics: IdentityStatistics
    metadata: IdentityMetadata

    @property
    def has_findings(self) -> bool:
        return bool(self.findings)
