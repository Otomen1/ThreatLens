"""Detection templates — reusable blueprints and their registry.

A :class:`~threatlens.detection.models.DetectionTemplate` fixes the language,
target, and category of a family of detections so every artifact of that family
is shaped and *identified* consistently. :func:`apply_template` is the single,
pure path a future generator uses to turn a template plus finding-derived content
into a content-addressed :class:`~threatlens.detection.models.DetectionArtifact`.

No concrete templates ship in this phase — :func:`build_default_template_registry`
returns an empty registry. The helper is fully implemented and tested so that
adding a generator later is a matter of registering templates and calling
:func:`apply_template`, never re-deriving identity or artifact shape.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from .engine import compute_artifact_id
from .models import (
    DetectionArtifact,
    DetectionReference,
    DetectionTemplate,
    DetectionValidation,
)
from .types import DetectionSeverity


def apply_template(
    template: DetectionTemplate,
    *,
    title: str,
    content: str = "",
    description: str = "",
    severity: DetectionSeverity = DetectionSeverity.INFORMATIONAL,
    source_finding_ids: Iterable[str] = (),
    references: Iterable[DetectionReference] = (),
    rule_id: str | None = None,
    metadata: Mapping[str, str] | None = None,
) -> DetectionArtifact:
    """Instantiate ``template`` into a deterministic artifact (pure).

    Computes the content-addressed id from stable values only and copies the
    template's language/target/category/capabilities onto the artifact. Validation
    is left ``UNVALIDATED`` — validators run in a later phase. ``severity`` is
    supplied by the caller (copied from the originating finding), never derived.
    """
    finding_ids = tuple(source_finding_ids)
    artifact_id = compute_artifact_id(
        language=template.language,
        target_platform=template.target.platform,
        category=template.category,
        content=content,
        rule_id=rule_id,
        source_finding_ids=finding_ids,
    )
    return DetectionArtifact(
        id=artifact_id,
        language=template.language,
        target=template.target,
        title=title,
        description=description,
        content=content,
        severity=severity,
        category=template.category,
        capabilities=template.capabilities,
        source_finding_ids=finding_ids,
        references=tuple(references),
        validation=DetectionValidation(),
        rule_id=rule_id,
        metadata=dict(metadata or {}),
    )


class DuplicateDetectionTemplateError(ValueError):
    """Raised when registering a template whose id already exists."""

    def __init__(self, template_id: str) -> None:
        super().__init__(f"a detection template with id {template_id!r} is already registered")
        self.template_id = template_id


class TemplateRegistry:
    """Holds detection templates keyed by unique id, exposed in id order."""

    def __init__(self) -> None:
        self._templates: dict[str, DetectionTemplate] = {}

    def register(self, template: DetectionTemplate) -> None:
        """Add a template; raise :class:`DuplicateDetectionTemplateError` on clash."""
        if template.id in self._templates:
            raise DuplicateDetectionTemplateError(template.id)
        self._templates[template.id] = template

    def get(self, template_id: str) -> DetectionTemplate | None:
        """Return the registered template with ``template_id``, or ``None``."""
        return self._templates.get(template_id)

    def __contains__(self, template_id: object) -> bool:
        return template_id in self._templates

    def __len__(self) -> int:
        return len(self._templates)

    @property
    def templates(self) -> tuple[DetectionTemplate, ...]:
        """All registered templates, ordered by id (deterministic)."""
        return tuple(self._templates[tid] for tid in sorted(self._templates))


def build_default_template_registry() -> TemplateRegistry:
    """Build the default template registry. **Empty in Phase 4.0.**"""
    return TemplateRegistry()
