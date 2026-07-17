"""Deterministic builders for Case Management tests."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from threatlens.cases import Case

NOW = datetime(2026, 7, 17, tzinfo=UTC)


def case(**overrides: object) -> Case:
    """Build a minimal, valid :class:`Case`."""
    defaults: dict[str, object] = {
        "id": uuid4(),
        "title": "Test case",
        "created_at": NOW,
        "updated_at": NOW,
    }
    defaults.update(overrides)
    return Case(**defaults)  # type: ignore[arg-type]
