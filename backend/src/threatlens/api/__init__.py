"""HTTP transport for ThreatLens.

:mod:`threatlens.api.app` is the composition root; each subsystem's endpoints
are defined in their own router under :mod:`threatlens.api.routes` (plus the
standalone ``health`` and ``system`` routers) and mounted there. Every route is
a thin layer: it validates input and delegates to the corresponding engine or
service, returning that subsystem's existing contract verbatim. No business
logic, persistence, caching, or auth lives in the API layer itself.
"""

from __future__ import annotations

from .app import app

__all__ = ["app"]
