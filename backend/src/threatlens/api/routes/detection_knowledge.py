"""Detection Knowledge Library routes: read-only recommend/search over COMMUNITY detections.

Kept deliberately separate from the generated ``DetectionPackage``: a community
detection is authored elsewhere, carries its own provenance, and is never
merged with generated content.
"""

from __future__ import annotations

import time
from typing import Annotated

from fastapi import APIRouter, Depends

from ...detection_library import (
    CommunityRecommendation,
    CommunitySearchResult,
    DetectionKnowledgeService,
    DetectionLanguage,
    DetectionSeverity,
    RulePlatform,
)
from ...reasoning import InvestigationSummary
from ...system import registry as metrics_registry
from ...system.record import record_dkl_query
from ..timing import elapsed_ms

router = APIRouter()

# The Detection Knowledge Library is a separate, read-only downstream consumer:
# it indexes *community* detection content and recommends it, never generating
# rules and never touching the Detection Engine. Built once, offline-first (the
# bundled seed corpus, or a synced cache when configured) — an investigation
# never reaches the network to serve a recommendation. Not underscore-prefixed:
# the Operational Dashboard's system router reads the same instance.
knowledge_service = DetectionKnowledgeService.from_default()


def get_knowledge_service() -> DetectionKnowledgeService:
    """Provide the Detection Knowledge Library service (overridable in tests)."""
    return knowledge_service


@router.post("/api/v1/detection-knowledge/recommend", response_model=CommunityRecommendation)
def recommend_community_detections(
    summary: InvestigationSummary,
    service: Annotated[DetectionKnowledgeService, Depends(get_knowledge_service)],
) -> CommunityRecommendation:
    """Recommend *community* detections that resemble a completed investigation.

    Strictly downstream, read-only, and deterministic (no AI, no embeddings, no
    network): the same summary always yields the same ranked exact/partial/
    related community rules. These are complementary to — never merged with — the
    generated ``DetectionPackage`` from ``/detections``; provenance (repository,
    author, license, version, URL) is preserved on every match.
    """
    _start = time.perf_counter()
    result = service.recommend(summary)
    record_dkl_query(metrics_registry, duration_ms=elapsed_ms(_start))
    return result


@router.get("/api/v1/detection-knowledge/search", response_model=CommunitySearchResult)
def search_community_detections(
    service: Annotated[DetectionKnowledgeService, Depends(get_knowledge_service)],
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
    """Search the offline community library by any combination of axes (AND).

    Every filter is optional; results are returned in a stable, deterministic
    order with a snapshot of library stats. Read-only and offline.
    """
    _start = time.perf_counter()
    result = service.search(
        ioc=ioc,
        technique=technique,
        actor=actor,
        malware=malware,
        name=name,
        tag=tag,
        rule_id=rule_id,
        language=language,
        repository=repository,
        min_severity=min_severity,
        platform=platform,
        text=text,
        limit=limit,
        offset=offset,
    )
    record_dkl_query(metrics_registry, duration_ms=elapsed_ms(_start))
    return result
