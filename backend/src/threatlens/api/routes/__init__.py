"""Per-subsystem API routers, composed by :mod:`threatlens.api.app`.

Each module owns one subsystem's endpoints and the process-wide singleton(s)
it needs (a service or registry, built once at import time). ``api/app.py``
imports each router and mounts it — it holds no route handlers of its own.
"""

from __future__ import annotations
