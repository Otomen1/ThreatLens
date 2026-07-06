"""Identity Intelligence Framework (Phase 6.0 — architecture only).

Threat Intelligence (``providers/``) answers "is this IOC malicious?" and
Exposure Intelligence (``exposure/``) answers "where is this entity exposed?"
— Identity Intelligence answers "what is known about this identity?" (breach
appearances, credential exposure, paste history, linked accounts, directory
profile, group membership, MFA state, sign-in activity, …). It is purely
descriptive: it never scores, never judges compromise, and shares no models,
registry, or provider logic with the other frameworks — dependency flows one
way, inward from this package to ``entities/`` only. Nothing in the frozen
subsystems imports from here, and this package imports from none of them.

Phase 6.0 ships the framework — models, provider interface, registry, config,
cache, service — with **zero** concrete providers; every code path
(registration, routing, aggregation, the service) is already real and tested
against an empty registry, exactly as Exposure Intelligence's Phase 5.0
framework-only milestone was. Phase 6.1+ registers concrete providers (HIBP,
Entra ID, Okta, …) against this unmodified contract.
"""

from __future__ import annotations

from .cache import IdentityCache, InMemoryIdentityCache
from .config import IdentityConfig
from .exceptions import (
    DuplicateIdentityProviderError,
    IdentityConfigurationError,
    IdentityError,
)
from .models import (
    IdentityAsset,
    IdentityCapability,
    IdentityFinding,
    IdentityFindingError,
    IdentityMetadata,
    IdentityProviderHealth,
    IdentityProviderMetadata,
    IdentityProviderStatus,
    IdentityReference,
    IdentityStatistics,
    IdentityStatus,
    IdentitySummary,
)
from .provider import IdentityProvider
from .registry import IdentityRegistry, build_default_registry
from .service import IDENTITY_FRAMEWORK_VERSION, IdentityService

__all__ = [
    "IDENTITY_FRAMEWORK_VERSION",
    "DuplicateIdentityProviderError",
    "IdentityAsset",
    "IdentityCache",
    "IdentityCapability",
    "IdentityConfig",
    "IdentityConfigurationError",
    "IdentityError",
    "IdentityFinding",
    "IdentityFindingError",
    "IdentityMetadata",
    "IdentityProvider",
    "IdentityProviderHealth",
    "IdentityProviderMetadata",
    "IdentityProviderStatus",
    "IdentityReference",
    "IdentityRegistry",
    "IdentityService",
    "IdentityStatistics",
    "IdentityStatus",
    "IdentitySummary",
    "InMemoryIdentityCache",
    "build_default_registry",
]
