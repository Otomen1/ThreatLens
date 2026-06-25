"""The normalized ``Entity`` returned by the detection engine.

Every detection — including unclassifiable input — returns a fully-formed
``Entity``. The shape matches the Phase 0 output contract: a resolved type,
the original and normalized values, a confidence score, the validation state,
any ambiguous alternatives, and a routing placeholder for the future source
router (Phase 1.2).
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from .types import EntityType, ValidationStatus


class RoutingMetadata(BaseModel):
    """Placeholder for source-routing metadata.

    Phase 1.1 always emits an empty provider list. The structure exists now so
    the Phase 1.2 source router can populate it without changing the contract.
    """

    model_config = ConfigDict(frozen=True)

    providers: list[str] = Field(default_factory=list)


class EntityMatch(BaseModel):
    """An alternative candidate type for ambiguous input.

    Surfaced in ``Entity.possible_matches`` so the caller can see (and later
    let a user override) competing interpretations instead of hiding them
    behind a single guessed answer.
    """

    model_config = ConfigDict(frozen=True)

    type: EntityType
    confidence: int = Field(ge=0, le=100)


class Entity(BaseModel):
    """The normalized unit of search produced by the detection engine."""

    model_config = ConfigDict(frozen=True)

    type: EntityType
    value: str
    normalized_value: str
    confidence: int = Field(ge=0, le=100)
    validation: ValidationStatus
    possible_matches: list[EntityMatch] = Field(default_factory=list)
    routing: RoutingMetadata = Field(default_factory=RoutingMetadata)
