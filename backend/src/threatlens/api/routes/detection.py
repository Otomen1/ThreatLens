"""Detection Engineering route: converts a completed investigation into a DetectionPackage."""

from __future__ import annotations

import time

from fastapi import APIRouter
from pydantic import BaseModel, Field

from ...detection import DetectionPackage, test_sigma_rule
from ...detection.types import DetectionLanguage
from ...detection import build_default_registry as build_detection_registry
from ...detection import generate as generate_detections
from ...reasoning import InvestigationSummary
from ...system import registry as metrics_registry
from ...system.record import record_detection_generation
from ..timing import elapsed_ms

router = APIRouter()


class DetectionTestRequest(BaseModel):
    language: DetectionLanguage
    content: str = Field(min_length=1)
    sample_logs: list[dict[str, object]] = Field(default_factory=list, max_length=500)


class DetectionTestResponse(BaseModel):
    valid: bool
    matched_logs: int
    total_logs: int
    messages: list[str] = Field(default_factory=list)

# The Detection Engineering registry is a downstream, deterministic consumer of
# the InvestigationSummary. Built once from the registered deterministic generators.
# Not underscore-prefixed: the Operational Dashboard's system router reads the
# same instance (see api/app.py).
detection_registry = build_detection_registry()


@router.post("/api/v1/detections/test", response_model=DetectionTestResponse)
def test_detection(request: DetectionTestRequest) -> DetectionTestResponse:
    """Offline rule test; never contacts a SIEM or external provider."""
    if request.language is not DetectionLanguage.SIGMA:
        return DetectionTestResponse(valid=False, matched_logs=0, total_logs=len(request.sample_logs), messages=["Offline sample matching currently supports Sigma JSON logs only."])
    valid, matched, messages = test_sigma_rule(request.content, tuple(request.sample_logs))
    return DetectionTestResponse(valid=valid, matched_logs=matched, total_logs=len(request.sample_logs), messages=list(messages))


@router.post("/api/v1/detections", response_model=DetectionPackage)
def create_detections(summary: InvestigationSummary) -> DetectionPackage:
    """Convert a completed investigation into a ``DetectionPackage``.

    The input is the deterministic ``InvestigationSummary`` produced by
    ``/investigate``; the output is a content-addressed ``DetectionPackage``. The
    Detection Engine is strictly downstream and pure — it never influences
    findings, confidence, severity, priority, recommendations, or relationships,
    and it has no access to providers or AI.

    The package may be empty when findings cannot produce platform-specific
    detections; otherwise it contains artifacts from the registered generators.
    """
    _start = time.perf_counter()
    package = generate_detections(summary, registry=detection_registry)
    record_detection_generation(metrics_registry, package=package, duration_ms=elapsed_ms(_start))
    return package
