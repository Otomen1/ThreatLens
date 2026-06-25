"""Vercel serverless entry point for the ThreatLens detection API.

Vercel deploys this module as a Python function and serves the exported ``app``
(ASGI). The rewrite in ``vercel.json`` routes ``/api/v1/*`` here; FastAPI matches
the original request path (e.g. ``/api/v1/detect``).

The engine source is vendored into ./vendor at build time (see
``scripts/vendor-engine.mjs``) because Vercel's Python builder cannot reach the
sibling ``../backend`` package above the root directory. We add that directory to
the import path so the same engine that powers local/Docker runs powers the
deployed site, with a single source of truth in ../backend.
"""

import sys
from pathlib import Path

_vendor = Path(__file__).resolve().parent.parent / "vendor"
if _vendor.is_dir() and str(_vendor) not in sys.path:
    sys.path.insert(0, str(_vendor))

from threatlens.api.app import app  # noqa: E402

__all__ = ["app"]
