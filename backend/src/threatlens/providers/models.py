"""Pydantic models describing a provider and its health.

Frozen and serializable, mirroring ``entities/models.py``. These carry only
metadata — never credentials, and never any network behavior.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from ..entities.types import EntityType
from .types import ProviderAuthType, ProviderCapability, ProviderStatus


class ProviderMetadata(BaseModel):
    """Static description of an intelligence provider.

    This is the contract the registry indexes and the router matches against.
    A provider is fully described by this object plus its (later) ``search``
    implementation.
    """

    model_config = ConfigDict(frozen=True)

    name: str = Field(min_length=1)  # machine identifier, e.g. "virustotal"
    display_name: str = Field(min_length=1)  # human label, e.g. "VirusTotal"
    supported_entity_types: frozenset[EntityType] = Field(min_length=1)
    capabilities: frozenset[ProviderCapability] = Field(default_factory=frozenset)
    # Lower runs first, matching the detector registry convention.
    priority: int = 100
    auth_type: ProviderAuthType = ProviderAuthType.API_KEY
    enabled: bool = True

    @property
    def requires_auth(self) -> bool:
        """Whether the provider needs credentials to operate."""
        return self.auth_type is not ProviderAuthType.NONE


class ProviderHealth(BaseModel):
    """A point-in-time health snapshot for a provider.

    Phase 1.2 performs no network probe; the status is derived from static state.
    The shape is stable so a real check can populate it later without changing
    callers.
    """

    model_config = ConfigDict(frozen=True)

    name: str
    status: ProviderStatus
    detail: str | None = None
