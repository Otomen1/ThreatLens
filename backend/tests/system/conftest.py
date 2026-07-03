"""Test isolation for the Operational Dashboard's process-wide metrics singleton.

``api/app.py`` mounts the system router closed over the *actual*
``threatlens.system.metrics.registry`` object, so tests reset it in place
(rather than swapping the module attribute, which the already-built router
would not see).
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from threatlens.system.metrics import registry


@pytest.fixture(autouse=True)
def _reset_metrics_registry() -> Iterator[None]:
    registry.reset()
    yield
    registry.reset()
