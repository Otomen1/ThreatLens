"""Exceptions for the Identity Intelligence Framework."""

from __future__ import annotations


class IdentityError(Exception):
    """Base class for all Identity Intelligence framework errors."""


class DuplicateIdentityProviderError(IdentityError):
    """Raised when registering a provider whose name is already registered."""

    def __init__(self, name: str) -> None:
        super().__init__(f"an identity provider named {name!r} is already registered")
        self.name = name


class IdentityConfigurationError(IdentityError):
    """Raised for an invalid Identity Intelligence configuration value."""
