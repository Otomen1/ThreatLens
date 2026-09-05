from threatlens.detection.models import DetectionArtifact, DetectionTarget
from threatlens.detection.types import DetectionLanguage
from threatlens.detection.validation import validate_artifact


def test_empty_detection_is_invalid() -> None:
    artifact = DetectionArtifact(
        id="det_test",
        language=DetectionLanguage.SIGMA,
        target=DetectionTarget(language=DetectionLanguage.SIGMA),
        title="test",
    )
    result = validate_artifact(artifact)
    assert result.status == "invalid"
    assert "empty" in result.messages[0]


def test_valid_sigma_shape_is_valid() -> None:
    artifact = DetectionArtifact(
        id="det_test",
        language=DetectionLanguage.SIGMA,
        target=DetectionTarget(language=DetectionLanguage.SIGMA),
        title="test",
        content=(
            "title: Test\nlogsource: {category: dns}\n"
            "detection: {sel: {query: example.com}, condition: sel}\n"
        ),
    )
    assert validate_artifact(artifact).status == "valid"
