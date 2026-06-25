"""Intelligence Provider Framework (Phase 1.2).

Determines which intelligence providers can enrich a detected entity. This
package is pure infrastructure — registry, base interface, metadata/capability
models, and deterministic routing — and performs NO external API calls. Concrete
providers (VirusTotal, AbuseIPDB, MalwareBazaar, OTX, …) arrive in later phases
and plug in here by declaring metadata and implementing ``search``; no existing
code changes when a provider is added.
"""

from __future__ import annotations

from .base import IntelligenceProvider
from .models import ProviderHealth, ProviderMetadata
from .registry import DuplicateProviderError, ProviderRegistry
from .router import ProviderRouter
from .types import ProviderAuthType, ProviderCapability, ProviderStatus

__all__ = [
    "DuplicateProviderError",
    "IntelligenceProvider",
    "ProviderAuthType",
    "ProviderCapability",
    "ProviderHealth",
    "ProviderMetadata",
    "ProviderRegistry",
    "ProviderRouter",
    "ProviderStatus",
]
