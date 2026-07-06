"""Detection Engineering route: converts a completed investigation into a DetectionPackage."""

from __future__ import annotations

import time

from fastapi import APIRouter

from ...detection import DetectionPackage
from ...detection import build_default_registry as build_detection_registry
from ...detection import generate as generate_detections
from ...reasoning import InvestigationSummary
from ...system import registry as metrics_registry
from ...system.record import record_detection_generation
from ..timing import elapsed_ms

router = APIRouter()

# The Detection Engineering registry is a downstream, deterministic consumer of
# the InvestigationSummary. Built once; empty in Phase 4.0 (no generators yet).
# Not underscore-prefixed: the Operational Dashboard's system router reads the
# same instance (see api/app.py).
detection_registry = build_detection_registry()


@router.post("/api/v1/detections", response_model=DetectionPackage)
def create_detections(summary: InvestigationSummary) -> DetectionPackage:
    """Convert a completed investigation into a ``DetectionPackage``.

    The input is the deterministic ``InvestigationSummary`` produced by
    ``/investigate``; the output is a content-addressed ``DetectionPackage``. The
    Detection Engine is strictly downstream and pure — it never influences
    findings, confidence, severity, priority, recommendations, or relationships,
    and it has no access to providers or AI.

    In Phase 4.0 no generators are registered, so the package is well-formed but
    carries no artifacts (``is_empty``). The endpoint and contract already exist
    so future generators light up without an API change.
    """
    _start = time.perf_counter()
    package = generate_detections(summary, registry=detection_registry)
    record_detection_generation(metrics_registry, package=package, duration_ms=elapsed_ms(_start))
    return package
