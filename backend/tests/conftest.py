"""Routine tests never contact live IOC repositories via the shared feed refresh."""

import os
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

# Explicit offline development policy for legacy API tests. Security tests
# override these settings; production never derives a bypass from pytest itself.
os.environ["PYTHON_DOTENV_DISABLED"] = "1"
os.environ["THREATLENS_ENV"] = "test"
os.environ["THREATLENS_ALLOW_UNAUTHENTICATED_LOCAL"] = "true"
os.environ["THREATLENS_OWNER_USER_ID"] = "00000000-0000-4000-8000-000000000001"
_test_data = tempfile.TemporaryDirectory(
    prefix=".test-owner-session-", dir=Path(__file__).resolve().parents[1]
)
os.environ["THREATLENS_CACHE_PATH"] = str(Path(_test_data.name) / "cache.json")
os.environ["THREATLENS_RATE_LIMIT_PATH"] = str(Path(_test_data.name) / "limits.json")
os.environ["THREATLENS_DATABASE_PATH"] = str(Path(_test_data.name) / "records.db")


@pytest.fixture(autouse=True)
def offline_ioc_refresh(monkeypatch, request):
    if request.node.path.name == "test_ioc_reports.py":
        return
    monkeypatch.setattr(
        "threatlens.threat_feed.service.collect_ioc_reports", AsyncMock(return_value=0)
    )
