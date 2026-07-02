"""The detection-generator registry and its extension points.

Mirrors the reasoning ``RuleRegistry`` and the provider registries: a small,
explicit container with no global mutable state, exposing generators in a
deterministic order. This is the seam future phases plug concrete generators
into (Sigma, YARA, Suricata, Snort, Splunk, Sentinel, Elastic, CrowdStrike,
Trend Vision One, Stellar Cyber).

Two abstractions are defined here:

* :class:`DetectionGenerator` — turns an ``InvestigationSummary`` into artifacts.
  **Pure**: no I/O, no providers, no AI. None ship in this phase.
* :class:`DetectionValidator` — validates an artifact against its toolchain
  (Sigma syntax, YARA compilation, KQL/SPL parsing, …). The interface exists so
  later phases can implement validators without touching the engine; **no
  validators are implemented now**.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Sequence

from ..reasoning import InvestigationSummary
from .models import DetectionArtifact, DetectionValidation
from .types import DetectionCapability, DetectionLanguage


class DetectionGenerator(ABC):
    """Produces detection artifacts from an investigation (pure, deterministic).

    A generator declares static metadata (``name``, ``language``,
    ``capabilities``, ``priority``) and implements :meth:`generate`. It must never
    perform I/O, contact a provider, call an AI model, or mutate the summary.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique machine identifier, e.g. ``"sigma"``."""

    @property
    @abstractmethod
    def language(self) -> DetectionLanguage:
        """The rule language this generator emits."""

    @property
    def capabilities(self) -> frozenset[DetectionCapability]:
        """The kinds of detection content this generator can express."""
        return frozenset()

    @property
    def priority(self) -> int:
        """Ordering hint (lower runs first); ties break on ``name``."""
        return 100

    @abstractmethod
    def generate(self, summary: InvestigationSummary) -> Sequence[DetectionArtifact]:
        """Return zero or more artifacts derived from ``summary`` (never raises)."""


class DetectionValidator(ABC):
    """Validates a generated artifact against its language/toolchain.

    Extension point only — no concrete validators exist in this phase. Future
    implementations (Sigma syntax, YARA compilation, Suricata/Snort parsing,
    Sentinel KQL, Splunk SPL) return a :class:`DetectionValidation` and must be
    side-effect-free and deterministic.
    """

    @property
    @abstractmethod
    def language(self) -> DetectionLanguage:
        """The language this validator understands."""

    @abstractmethod
    def validate(self, artifact: DetectionArtifact) -> DetectionValidation:
        """Return a validation result for ``artifact`` (never raises)."""


class DuplicateDetectionGeneratorError(ValueError):
    """Raised when registering a generator whose name is already registered."""

    def __init__(self, name: str) -> None:
        super().__init__(f"a detection generator named {name!r} is already registered")
        self.name = name


class DetectionRegistry:
    """Holds detection generators keyed by unique name, ordered deterministically."""

    def __init__(self) -> None:
        self._generators: dict[str, DetectionGenerator] = {}

    def register(self, generator: DetectionGenerator) -> None:
        """Add a generator; raise :class:`DuplicateDetectionGeneratorError` on clash."""
        name = generator.name
        if name in self._generators:
            raise DuplicateDetectionGeneratorError(name)
        self._generators[name] = generator

    def get(self, name: str) -> DetectionGenerator | None:
        """Return the registered generator with ``name``, or ``None``."""
        return self._generators.get(name)

    def __contains__(self, name: object) -> bool:
        return name in self._generators

    def __len__(self) -> int:
        return len(self._generators)

    @property
    def generators(self) -> tuple[DetectionGenerator, ...]:
        """All generators, ordered by ascending priority then name (deterministic)."""
        return tuple(
            sorted(
                self._generators.values(),
                key=lambda g: (g.priority, g.name),
            )
        )

    @property
    def languages(self) -> tuple[DetectionLanguage, ...]:
        """The distinct languages the registered generators emit."""
        return tuple(sorted({g.language for g in self._generators.values()}, key=lambda x: x.value))


def build_default_registry() -> DetectionRegistry:
    """Build the default generator registry.

    **Empty in Phase 4.0.** This is the single wiring point for future
    generators — registering Sigma/YARA/Suricata/… here is the only change
    needed to light them up, exactly as ``providers.defaults`` wires providers.
    """
    return DetectionRegistry()
