"""Metadata describing a reference knowledge provider and its dataset.

Distinct from ``providers.ProviderMetadata``: reference sources are static and
versioned, so the metadata carries dataset provenance (version, release date,
source, offline/online, last sync) instead of auth requirements. The provenance
fields are reusable by every future reference provider (MITRE, NVD, CWE, CAPEC).
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from ..entities.types import EntityType
from .types import ReferenceCapability


class ReferenceMetadata(BaseModel):
    """Static description of a reference knowledge provider."""

    model_config = ConfigDict(frozen=True)

    name: str = Field(min_length=1)  # machine id, e.g. "mitre_attack"
    display_name: str = Field(min_length=1)  # e.g. "MITRE ATT&CK"
    supported_entity_types: frozenset[EntityType] = Field(min_length=1)
    capabilities: frozenset[ReferenceCapability] = Field(default_factory=frozenset)
    # Lower runs first, matching the TI provider/detector convention.
    priority: int = 100
    enabled: bool = True

    # --- dataset provenance ---
    provider_version: str = "0.1.0"  # the provider implementation's version
    dataset_version: str | None = None  # e.g. ATT&CK "v15.1"
    release_date: str | None = None  # the dataset's published date (ISO or label)
    source_url: str | None = None  # canonical source of the dataset
    offline: bool = True  # bundled/cached locally vs. queried online
    last_updated: datetime | None = None  # when the local copy was last synced
