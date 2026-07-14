"""Tiny elapsed-time helper shared by every metrics-recording route."""

from __future__ import annotations

from time import perf_counter


def elapsed_ms(start: float) -> float:
    """Milliseconds elapsed since ``start`` (a ``time.perf_counter()`` reading)."""
    return (perf_counter() - start) * 1000
