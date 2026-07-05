"""Tests for ExposureConfig.from_env()."""

from __future__ import annotations

from threatlens.exposure.config import ExposureConfig


class TestDefaults:
    def test_disabled_by_default(self) -> None:
        config = ExposureConfig.from_env({})
        assert config.enabled is False

    def test_cache_enabled_by_default(self) -> None:
        config = ExposureConfig.from_env({})
        assert config.cache_enabled is True

    def test_default_timeout(self) -> None:
        config = ExposureConfig.from_env({})
        assert config.timeout == 10.0

    def test_no_rate_limit_by_default(self) -> None:
        config = ExposureConfig.from_env({})
        assert config.rate_limit_per_minute is None

    def test_no_provider_overrides_by_default(self) -> None:
        config = ExposureConfig.from_env({})
        assert config.provider_overrides == {}


class TestOverrides:
    def test_enabled_from_env(self) -> None:
        config = ExposureConfig.from_env({"EXPOSURE_ENABLED": "true"})
        assert config.enabled is True

    def test_cache_disabled_from_env(self) -> None:
        config = ExposureConfig.from_env({"EXPOSURE_CACHE_ENABLED": "false"})
        assert config.cache_enabled is False

    def test_timeout_from_env(self) -> None:
        config = ExposureConfig.from_env({"EXPOSURE_TIMEOUT": "30"})
        assert config.timeout == 30.0

    def test_invalid_timeout_falls_back_to_default(self) -> None:
        config = ExposureConfig.from_env({"EXPOSURE_TIMEOUT": "not-a-number"})
        assert config.timeout == 10.0

    def test_rate_limit_from_env(self) -> None:
        config = ExposureConfig.from_env({"EXPOSURE_RATE_LIMIT_PER_MINUTE": "100"})
        assert config.rate_limit_per_minute == 100

    def test_config_is_frozen(self) -> None:
        config = ExposureConfig.from_env({})
        try:
            config.enabled = True  # type: ignore[misc]
            raised = False
        except Exception:
            raised = True
        assert raised
