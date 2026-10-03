"""Routine tests never contact live IOC repositories via the shared feed refresh."""

from unittest.mock import AsyncMock

import pytest


@pytest.fixture(autouse=True)
def offline_ioc_refresh(monkeypatch, request):
    if request.node.path.name == "test_ioc_reports.py":
        return
    monkeypatch.setattr(
        "threatlens.threat_feed.service.collect_ioc_reports", AsyncMock(return_value=0)
    )
