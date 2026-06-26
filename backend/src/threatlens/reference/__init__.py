"""Reference Knowledge Provider Framework (Phase 1.8).

A framework, parallel to ``threatlens.providers``, for static/versioned
cybersecurity knowledge sources — MITRE ATT&CK, NVD, CWE, CAPEC, ATT&CK
groups/software, and a future internal knowledge base or report index. It is
pure infrastructure (base interface, metadata, registry, deterministic router)
and ships no concrete providers; those arrive in later phases (MITRE first).

Reference providers return the *shared* canonical
``providers.IntelligenceResult`` (with no reputation), so the future combined
"ThreatLens Intelligence Document" merges TI and reference results through the
existing ``providers.aggregate`` — no new aggregation engine.
"""

from __future__ import annotations

from .base import ReferenceProvider
from .models import ReferenceMetadata
from .registry import DuplicateReferenceProviderError, ReferenceRegistry
from .router import ReferenceRouter
from .types import ReferenceCapability

__all__ = [
    "DuplicateReferenceProviderError",
    "ReferenceCapability",
    "ReferenceMetadata",
    "ReferenceProvider",
    "ReferenceRegistry",
    "ReferenceRouter",
]
