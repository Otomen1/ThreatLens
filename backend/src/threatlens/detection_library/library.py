"""The indexed, searchable Detection Knowledge Library (Phase 4.6).

An in-memory, immutable index over a set of normalized :class:`CommunityRule`s.
Built once from the provider registry (or the synced cache) and then queried
offline — no network, no clock. Search supports every axis the spec calls for:
IOC, MITRE technique, threat actor, malware family, rule name, tags, rule id,
language, repository, severity, and platform. Results are always in a stable,
deterministic order.
"""

from __future__ import annotations

from collections import Counter

from .models import (
    CommunityRule,
    CommunitySearchResult,
    LibraryStats,
)
from .types import DetectionLanguage, DetectionSeverity, RulePlatform, SyncStatus


class DetectionLibrary:
    """An immutable, indexed collection of community detection rules."""

    def __init__(
        self,
        rules: tuple[CommunityRule, ...],
        *,
        sync_status: SyncStatus = SyncStatus.SEED,
        version: str = "1.0",
    ) -> None:
        # Canonical, deduplicated order: by source priority, source id, then rule id.
        ordered = sorted(
            {rule.id: rule for rule in rules}.values(),
            key=lambda r: (r.source.priority, r.source.id, r.id),
        )
        self._rules: tuple[CommunityRule, ...] = tuple(ordered)
        self._sync_status = sync_status
        self._version = version

    @property
    def rules(self) -> tuple[CommunityRule, ...]:
        return self._rules

    @property
    def sync_status(self) -> SyncStatus:
        return self._sync_status

    @property
    def version(self) -> str:
        return self._version

    def __len__(self) -> int:
        return len(self._rules)

    # --- search ------------------------------------------------------------- #

    def search(
        self,
        *,
        ioc: str | None = None,
        technique: str | None = None,
        actor: str | None = None,
        malware: str | None = None,
        name: str | None = None,
        tag: str | None = None,
        rule_id: str | None = None,
        language: DetectionLanguage | None = None,
        repository: str | None = None,
        min_severity: DetectionSeverity | None = None,
        platform: RulePlatform | None = None,
        text: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> CommunitySearchResult:
        """Return rules matching every provided filter (AND), in stable order."""
        filters: dict[str, object] = {
            "ioc": ioc,
            "technique": technique,
            "actor": actor,
            "malware": malware,
            "name": name,
            "tag": tag,
            "rule_id": rule_id,
            "language": language,
            "repository": repository,
            "min_severity": min_severity,
            "platform": platform,
            "text": text,
        }
        matches = [rule for rule in self._rules if self._matches(rule, filters)]
        total = len(matches)
        page = tuple(matches[offset : offset + limit]) if limit >= 0 else tuple(matches[offset:])
        return CommunitySearchResult(total=total, rules=page, stats=self.stats())

    @staticmethod
    def _matches(rule: CommunityRule, f: dict[str, object]) -> bool:
        if (ioc := f.get("ioc")) and not _has_ioc(rule, str(ioc)):
            return False
        if (tech := f.get("technique")) and not _has_technique(rule, str(tech)):
            return False
        if (actor := f.get("actor")) and not _contains(rule.threat_actors, str(actor)):
            return False
        if (malware := f.get("malware")) and not _contains(rule.malware_families, str(malware)):
            return False
        if (name := f.get("name")) and str(name).lower() not in rule.name.lower():
            return False
        if (tag := f.get("tag")) and str(tag).lower() not in {t.lower() for t in rule.tags}:
            return False
        if (rid := f.get("rule_id")) and str(rid).lower() not in (
            rule.rule_id.lower(),
            rule.id.lower(),
        ):
            return False
        if (language := f.get("language")) and rule.language is not language:
            return False
        if (repo := f.get("repository")) and rule.source.id != str(repo):
            return False
        if (sev := f.get("min_severity")) is not None and rule.severity < sev:  # type: ignore[operator]
            return False
        if (plat := f.get("platform")) and plat not in rule.platforms:
            return False
        text = f.get("text")
        return not text or _matches_text(rule, str(text))

    # --- stats -------------------------------------------------------------- #

    def stats(self) -> LibraryStats:
        by_language = Counter(rule.language.value for rule in self._rules)
        by_source = Counter(rule.source.id for rule in self._rules)
        return LibraryStats(
            total_rules=len(self._rules),
            sources=len(by_source),
            sync_status=self._sync_status,
            by_language=dict(sorted(by_language.items())),
            by_source=dict(sorted(by_source.items())),
            library_version=self._version,
        )


# --------------------------------------------------------------------------- #
# Pure filter predicates
# --------------------------------------------------------------------------- #


def _has_ioc(rule: CommunityRule, value: str) -> bool:
    needle = value.strip().lower()
    return any(needle == i.value.strip().lower() for i in rule.iocs)


def _has_technique(rule: CommunityRule, value: str) -> bool:
    needle = value.strip().upper()
    return any(t == needle or t.startswith(needle + ".") for t in rule.mitre_techniques)


def _contains(values: tuple[str, ...], needle: str) -> bool:
    lowered = needle.strip().lower()
    return any(lowered in v.lower() for v in values)


def _matches_text(rule: CommunityRule, text: str) -> bool:
    needle = text.strip().lower()
    haystack = " ".join([rule.name, rule.description, rule.rule_id, " ".join(rule.tags)]).lower()
    return needle in haystack
