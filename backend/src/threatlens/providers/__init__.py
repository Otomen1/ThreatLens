"""Intelligence Provider Framework (Phase 1.2+).

Determines which intelligence providers can enrich a detected entity, and hosts
the concrete providers themselves. The framework (registry, base interface,
metadata/capability models, router, canonical result) performs no network I/O;
concrete providers (e.g. MalwareBazaar) do, behind the shared HTTP client. New
providers plug in by declaring metadata and implementing ``search`` and are
wired in one place — ``defaults.build_default_registry``.
"""

from __future__ import annotations

from .aggregation import (
    AggregatedResult,
    AttributedEvidence,
    AttributedReference,
    AttributedRelationship,
    ProviderSummary,
    aggregate,
)
from .base import IntelligenceProvider
from .defaults import build_default_registry, build_default_router
from .http import HttpClient, ProviderHttpError, ProviderNetworkError, ProviderTimeout
from .malwarebazaar import MalwareBazaarProvider
from .models import ProviderHealth, ProviderMetadata
from .registry import DuplicateProviderError, ProviderRegistry
from .results import (
    Evidence,
    EvidenceType,
    IntelligenceResult,
    Reference,
    Relationship,
    RelationshipTargetType,
    RelationshipType,
    Reputation,
    ReputationLevel,
    ResultError,
    ResultStatus,
)
from .router import ProviderRouter
from .types import ProviderAuthType, ProviderCapability, ProviderStatus

__all__ = [
    "AggregatedResult",
    "AttributedEvidence",
    "AttributedReference",
    "AttributedRelationship",
    "DuplicateProviderError",
    "Evidence",
    "EvidenceType",
    "HttpClient",
    "IntelligenceProvider",
    "IntelligenceResult",
    "MalwareBazaarProvider",
    "ProviderAuthType",
    "ProviderCapability",
    "ProviderHealth",
    "ProviderHttpError",
    "ProviderMetadata",
    "ProviderNetworkError",
    "ProviderRegistry",
    "ProviderRouter",
    "ProviderStatus",
    "ProviderSummary",
    "ProviderTimeout",
    "Reference",
    "Relationship",
    "RelationshipTargetType",
    "RelationshipType",
    "Reputation",
    "ReputationLevel",
    "ResultError",
    "ResultStatus",
    "aggregate",
    "build_default_registry",
    "build_default_router",
]
