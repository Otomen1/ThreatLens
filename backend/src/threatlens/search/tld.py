"""Offline TLD extraction shared by the network detectors.

tldextract is configured to use its bundled Public Suffix List snapshot and to
never reach the network (``suffix_list_urls=()``). This keeps classification
deterministic, fast, and dependency-free at runtime — a requirement for a
detection engine that must behave identically in CI and offline self-hosts.
"""

from __future__ import annotations

import tldextract

# No network fetch; rely on the snapshot packaged with tldextract.
extract = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)
