"""Unified investigation service (Phase 1.815)."""

from __future__ import annotations

from .cache import InvestigationCache, cache_key
from .service import InvestigationService

__all__ = ["InvestigationCache", "InvestigationService", "cache_key"]
