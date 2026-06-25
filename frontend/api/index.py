"""Vercel serverless entry point for the ThreatLens detection API.

Vercel deploys this module as a Python function and serves the exported ``app``
(ASGI). The rewrite in ``vercel.json`` routes ``/api/v1/*`` here; FastAPI matches
the original request path (e.g. ``/api/v1/detect``).

The detection engine is installed from ``../backend`` via ``requirements.txt``,
so the same engine that powers local/Docker runs powers the deployed site — no
detection logic is duplicated for the serverless target.
"""

from threatlens.api.app import app

__all__ = ["app"]
