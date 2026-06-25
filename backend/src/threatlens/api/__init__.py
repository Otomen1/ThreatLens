"""HTTP transport for the Universal Entity Detection Engine.

Phase 1.1.5 exposes the deterministic engine over a single REST endpoint so the
frontend can classify arbitrary input. The API is a thin layer: it validates
input, delegates to :func:`threatlens.search.detect`, and returns the existing
:class:`~threatlens.entities.models.Entity` contract verbatim. No threat
intelligence, AI, source routing, persistence, caching, or auth lives here.
"""

from __future__ import annotations

from .app import app

__all__ = ["app"]
