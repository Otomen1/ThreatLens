"""Exceptions for the Exposure Intelligence Framework."""

from __future__ import annotations


class ExposureError(Exception):
    """Base class for all Exposure Intelligence framework errors."""


class DuplicateExposureProviderError(ExposureError):
    """Raised when registering a provider whose name is already registered."""

    def __init__(self, name: str) -> None:
        super().__init__(f"an exposure provider named {name!r} is already registered")
        self.name = name


class ExposureConfigurationError(ExposureError):
    """Raised for an invalid Exposure Intelligence configuration value."""
