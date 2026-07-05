"""Test isolation for exposure provider tests from local environment state.

Provider constructors resolve unset credentials via ``os.getenv`` at
construction time (mirroring ``providers/abuseipdb.py``'s established
pattern) — correct for real deployments, but it means a developer's own
populated ``backend/.env`` (e.g. a real ``SHODAN_API_KEY`` for actual use)
leaks into ``os.environ`` via ``api/app.py``'s ``load_dotenv()`` the moment
any test imports it, silently changing what "no credentials configured"
tests actually exercise. This fixture clears the provider-credential env
vars before every test in this package so the suite's outcome never depends
on what happens to be in a local ``.env``.
"""

from __future__ import annotations

import pytest

_PROVIDER_ENV_VARS = (
    "SHODAN_API_KEY",
    "SHODAN_ENABLED",
    "SHODAN_BASE_URL",
    "SHODAN_TIMEOUT",
    "CENSYS_API_ID",
    "CENSYS_API_SECRET",
    "CENSYS_ENABLED",
    "CENSYS_BASE_URL",
    "CENSYS_TIMEOUT",
)


@pytest.fixture(autouse=True)
def _clear_provider_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in _PROVIDER_ENV_VARS:
        monkeypatch.delenv(name, raising=False)
