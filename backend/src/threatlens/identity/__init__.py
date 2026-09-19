"""Identity Intelligence Framework.

Threat Intelligence (``providers/``) answers "is this IOC malicious?" and
Exposure Intelligence (``exposure/``) answers "where is this entity exposed?"
— Identity Intelligence answers "what is known about this identity?" (breach
appearances, credential exposure, paste history, linked accounts, directory
profile, group membership, MFA state, sign-in activity, …). It is purely
descriptive: it never scores, never judges compromise, and shares no models,
registry, or provider logic with the other frameworks — dependency flows one
way, inward from this package to ``entities/`` only. Nothing in the frozen
subsystems imports from here, and this package imports from none of them.

The framework includes an optional HIBP email-breach provider, a one-hour
process-local cache, dedicated API routes, and a browser-local personal
workspace. Password exposure checks use a hash-prefix range lookup and never
send or persist plaintext passwords.
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
