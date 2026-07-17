"""Deterministic builders for Intelligence Collections tests.

Lives at ``tests/intel_collections/`` rather than ``tests/collections/`` —
the name every other subsystem's test directory would suggest — because this
repository's ``tests/`` root has no ``__init__.py``, so pytest's default
import mode would resolve a ``tests/collections/`` package as the bare
top-level module ``collections``, colliding with the Python standard
library's own ``collections`` package (which
``threatlens.collections.config`` itself imports ``collections.abc.Mapping``
from). Confirmed empirically before choosing this name; the *source* package
this tests — ``threatlens.collections`` — is unaffected, since it is only
ever reachable via its full dotted path.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from threatlens.collections import Collection, Indicator, IndicatorType

NOW = datetime(2026, 7, 17, tzinfo=UTC)


def collection(**overrides: object) -> Collection:
    """Build a minimal, valid :class:`Collection`."""
    defaults: dict[str, object] = {
        "id": uuid4(),
        "name": "Test collection",
        "created_at": NOW,
        "updated_at": NOW,
    }
    defaults.update(overrides)
    return Collection(**defaults)  # type: ignore[arg-type]


def indicator(**overrides: object) -> Indicator:
    """Build a minimal, valid :class:`Indicator`."""
    defaults: dict[str, object] = {
        "type": IndicatorType.DOMAIN,
        "value": "evil.example.com",
    }
    defaults.update(overrides)
    return Indicator(**defaults)  # type: ignore[arg-type]
