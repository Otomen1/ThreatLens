import pytest

from threatlens.detection import changed_fields, create_version, version_digest
from threatlens.detection.models import DetectionArtifact
from threatlens.detection.types import DetectionLanguage, DetectionReviewStatus


def artifact(**updates: object) -> DetectionArtifact:
    base = {
        "id": "det_test",
        "language": DetectionLanguage.SIGMA,
        "target": {"language": DetectionLanguage.SIGMA, "platform": "generic"},
        "title": "Test rule",
        "content": "title: test\n",
        "metadata": {"engine_version": "1.0", "mapping_version": "default"},
    }
    base.update(updates)
    return DetectionArtifact(**base)


def test_changed_fields_is_stable_and_specific() -> None:
    assert changed_fields(None, artifact()) == ("created",)
    assert changed_fields(artifact(), artifact(content="title: changed\n")) == ("content",)


def test_version_carries_mapping_and_digest() -> None:
    version = create_version(artifact(), version=2, reviewer="analyst")
    assert version.version == 2
    assert version.mapping_version == "default"
    assert version.reviewer == "analyst"
    assert version_digest(version) == version_digest(version)


def test_approved_snapshot_cannot_be_mutated_in_place() -> None:
    approved = artifact(review_status=DetectionReviewStatus.APPROVED)
    with pytest.raises(ValueError, match="immutable"):
        create_version(artifact(content="changed\n"), previous=approved)
