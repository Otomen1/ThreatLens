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
from .cwe import CweDataset, CweProvider
from .defaults import build_default_reference_registry, build_default_reference_router
from .mitre_attack import MitreAttackDataset, MitreAttackProvider
from .models import ReferenceMetadata
from .nvd import NvdDataset, NvdProvider
from .registry import DuplicateReferenceProviderError, ReferenceRegistry
from .router import ReferenceRouter
from .types import ReferenceCapability

__all__ = [
    "CweDataset",
    "CweProvider",
    "DuplicateReferenceProviderError",
    "MitreAttackDataset",
    "MitreAttackProvider",
    "NvdDataset",
    "NvdProvider",
    "ReferenceCapability",
    "ReferenceMetadata",
    "ReferenceProvider",
    "ReferenceRegistry",
    "ReferenceRouter",
    "build_default_reference_registry",
    "build_default_reference_router",
]
