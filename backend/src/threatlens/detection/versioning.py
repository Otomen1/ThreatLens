"""Pure, auditable detection version helpers.

The helpers deliberately keep history separate from the generated artifact.
Approved snapshots are immutable; a new edit must create a new version.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime

from .models import DetectionArtifact


@dataclass(frozen=True)
class DetectionVersion:
    version: int
    artifact_id: str
    content: str
    changed_fields: tuple[str, ...]
    mapping_version: str
    engine_version: str
    created_at: datetime
    reviewer: str | None = None
    approved: bool = False


def changed_fields(previous: DetectionArtifact | None, current: DetectionArtifact) -> tuple[str, ...]:
    """Return stable field names changed between two artifact snapshots."""
    if previous is None:
        return ("created",)
    fields = ("content", "title", "description", "severity", "category", "metadata")
    return tuple(name for name in fields if getattr(previous, name) != getattr(current, name))


def create_version(
    current: DetectionArtifact,
    *,
    previous: DetectionArtifact | None = None,
    version: int = 1,
    reviewer: str | None = None,
    approved: bool = False,
) -> DetectionVersion:
    """Create an immutable audit snapshot from an artifact."""
    if version < 1:
        raise ValueError("detection versions start at 1")
    if previous is not None and previous.review_status.value == "approved" and previous.content != current.content:
        # Approved artifacts can be superseded, but not mutated in place.
        if previous.id == current.id:
            raise ValueError("approved detection versions are immutable")
    return DetectionVersion(
        version=version,
        artifact_id=current.id,
        content=current.content,
        changed_fields=changed_fields(previous, current),
        mapping_version=current.metadata.get("mapping_version", "default"),
        engine_version=current.metadata.get("engine_version", "unknown"),
        created_at=datetime.now(UTC),
        reviewer=reviewer,
        approved=approved,
    )


def version_digest(version: DetectionVersion) -> str:
    """Stable digest for an exported version snapshot."""
    payload = "|".join((version.artifact_id, str(version.version), version.content))
    return hashlib.sha256(payload.encode()).hexdigest()[:16]
