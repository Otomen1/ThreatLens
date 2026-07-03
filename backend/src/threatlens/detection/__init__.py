"""Detection Engineering Framework (Phase 4.0).

A downstream, deterministic consumer of the frozen
:class:`~threatlens.reasoning.models.InvestigationSummary`. It converts findings
into reusable detection content — a :class:`DetectionPackage` — through one pure
entry point, :func:`generate`.

The Detection Engine is a **pure consumer**: it never performs investigations,
contacts providers, calls AI, or modifies findings, confidence, severity,
priority, recommendations, or relationships. The Reasoning Engine remains the
only source of truth.

This phase builds the framework only — canonical models, the pure engine,
content-addressed identity, an (empty) generator registry, template
infrastructure, and validation extension points. No generators, no Sigma, no
YARA, no AI, no rule generation; those arrive in later phases (see
``detection.future``).
"""

from __future__ import annotations

from .config import DetectionSettings
from .engine import (
    DETECTION_ENGINE_VERSION,
    compute_artifact_id,
    compute_package_id,
    generate,
)
from .future import (
    ChronicleGenerator,
    ElasticGenerator,
    QRadarGenerator,
    SentinelGenerator,
    SigmaGenerator,
    SnortGenerator,
    SplunkGenerator,
    SuricataGenerator,
    YaraGenerator,
)
from .models import (
    DetectionArtifact,
    DetectionMetadata,
    DetectionPackage,
    DetectionReference,
    DetectionTarget,
    DetectionTemplate,
    DetectionValidation,
)
from .registry import (
    DetectionGenerator,
    DetectionRegistry,
    DetectionValidator,
    DuplicateDetectionGeneratorError,
    build_default_registry,
)
from .templates import (
    DuplicateDetectionTemplateError,
    TemplateRegistry,
    apply_template,
    build_default_template_registry,
)
from .types import (
    DetectionCapability,
    DetectionCategory,
    DetectionLanguage,
    DetectionSeverity,
    DetectionValidationStatus,
)

__all__ = [
    "DETECTION_ENGINE_VERSION",
    "DetectionArtifact",
    "DetectionCapability",
    "DetectionCategory",
    "DetectionGenerator",
    "DetectionLanguage",
    "DetectionMetadata",
    "DetectionPackage",
    "DetectionReference",
    "DetectionRegistry",
    "DetectionSettings",
    "DetectionSeverity",
    "DetectionTarget",
    "DetectionTemplate",
    "DetectionValidation",
    "DetectionValidationStatus",
    "DetectionValidator",
    "DuplicateDetectionGeneratorError",
    "DuplicateDetectionTemplateError",
    "ChronicleGenerator",
    "ElasticGenerator",
    "QRadarGenerator",
    "SentinelGenerator",
    "SigmaGenerator",
    "SnortGenerator",
    "SplunkGenerator",
    "SuricataGenerator",
    "TemplateRegistry",
    "YaraGenerator",
    "apply_template",
    "build_default_registry",
    "build_default_template_registry",
    "compute_artifact_id",
    "compute_package_id",
    "generate",
]
