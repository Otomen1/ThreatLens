"""Reasoning-engine regression benchmark package (Phase 3.15).

A deterministic, offline corpus of investigation scenarios that pins the
:func:`threatlens.reasoning.reason` input → output contract. Each scenario
declares synthetic aggregation inputs (faithful to what real providers emit) and
the expected findings / severity / confidence / recommendations / priority. The
suite is part of CI: a future engine change that alters any pinned output fails
the build, surfacing unintended regressions before downstream features (AI,
detection engineering, exposure intelligence) depend on the engine.
"""
