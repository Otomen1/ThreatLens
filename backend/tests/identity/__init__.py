"""Offline tests for the Identity Intelligence Framework (Phase 6.0).

Zero network, zero live providers, zero API keys — mirrors
``tests/exposure/`` Phase 5.0 framework-only coverage: models, the provider
ABC's stub/health/safe-lookup behavior, registry routing, config, the
in-memory cache, aggregation, the service, and the ``GET /api/v1/identity``
endpoint.
"""

from __future__ import annotations
