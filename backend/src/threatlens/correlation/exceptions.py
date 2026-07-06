"""Exceptions for the Investigation Correlation Engine."""

from __future__ import annotations


class CorrelationError(Exception):
    """Base class for all Correlation Engine errors."""


class DuplicateCorrelationRuleError(CorrelationError):
    """Raised when registering a rule whose id is already registered."""

    def __init__(self, rule_id: str) -> None:
        super().__init__(f"a correlation rule with id {rule_id!r} is already registered")
        self.rule_id = rule_id


class CorrelationConfigurationError(CorrelationError):
    """Raised for an invalid Correlation Engine configuration value."""
