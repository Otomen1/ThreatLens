"""Shared credential resolution for abuse.ch providers.

abuse.ch issues a single Auth-Key that works across all its services
(MalwareBazaar, URLhaus, ThreatFox, …). So both providers resolve their key from
the same set of environment variables — whichever the operator set is used —
preferring the canonical ``ABUSE_CH_AUTH_KEY`` but accepting the per-service
names too. This means one configured key authenticates every abuse.ch provider.
"""

from __future__ import annotations

import os

_ABUSE_CH_ENVS: tuple[str, ...] = (
    "ABUSE_CH_AUTH_KEY",
    "MALWAREBAZAAR_AUTH_KEY",
    "URLHAUS_AUTH_KEY",
)


def abuse_ch_auth_key() -> str | None:
    """Return the first configured abuse.ch Auth-Key, or ``None``."""
    for name in _ABUSE_CH_ENVS:
        value = os.getenv(name)
        if value:
            return value
    return None
