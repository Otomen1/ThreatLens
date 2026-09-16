from __future__ import annotations

from pydantic import BaseModel

from threatlens.investigation.cache import InvestigationCache, cache_key


class _Payload(BaseModel):
    value: str


def test_memory_cache_round_trip(monkeypatch) -> None:
    monkeypatch.setenv("THREATLENS_STORAGE_BACKEND", "file")
    cache = InvestigationCache()
    entry = cache.set("key", _Payload(value="safe"))

    assert cache.get("key") == entry
    assert entry.payload == {"value": "safe"}
    assert entry.expires_at > entry.cached_at


def test_cache_key_changes_with_mode_and_provider_configuration(monkeypatch) -> None:
    common = {"entity_type": "domain", "value": "example.com", "providers": ["otx"]}
    standard = cache_key(scan_mode="standard", **common)
    assert cache_key(scan_mode="fast", **common) != standard

    monkeypatch.setenv("OTX_API_KEY", "rotated-key")
    assert cache_key(scan_mode="standard", **common) != standard


def test_cache_delete_removes_entry(monkeypatch) -> None:
    monkeypatch.setenv("THREATLENS_STORAGE_BACKEND", "file")
    cache = InvestigationCache()
    cache.set("key", _Payload(value="safe"))
    cache.delete("key")
    assert cache.get("key") is None
