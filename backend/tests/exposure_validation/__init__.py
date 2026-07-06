"""Exposure Engine validation & freeze suite (Phase 5.4).

Mirrors ``tests/detection/`` (Detection Engine v1.0 freeze) and
``tests/validation``/``tests/benchmark`` (Reasoning Engine v1.0 freeze): a
dedicated package, separate from the per-provider unit tests in
``tests/exposure/``, that validates the framework's routing, merge,
determinism, and contract behavior across provider combinations using
controllable fake providers — no network, no real provider credentials.
"""

from __future__ import annotations
