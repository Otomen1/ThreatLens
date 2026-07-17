"""Data models for the Intelligence Collections Framework (Phase 9.1).

A Collection is a reusable, analyst-curated set of threat intelligence —
"Silver Fox Campaign", "APT29 Infrastructure", "Internal Blocklist" — built
manually or seeded from a Workspace investigation or a Case. It is
deliberately NOT an analytical engine: nothing here detects, scores,
enriches, or classifies anything. A Collection stores exactly the
intelligence an analyst explicitly gives it, and references — never copies —
the Workspace investigations and Cases it was drawn from or is relevant to.

Relationship to the rest of the platform: ``Workspace -> Case -> Collection``
is a conceptual hierarchy, not an enforced one — a Collection may reference
zero or more Workspace investigations and zero or more Cases directly (it
does not need to go through a Case to reference a Workspace investigation).
Nothing here ever mutates a Workspace investigation or a Case; both remain
exactly as owned by their own subsystems.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from uuid import UUID

from pydantic import BaseModel, Field, JsonValue

COLLECTION_FRAMEWORK_VERSION = "1.0"

MAX_NAME_LENGTH = 200
MAX_DESCRIPTION_LENGTH = 2000
MAX_CATEGORY_LENGTH = 100
MAX_VALUE_LENGTH = 2048
MAX_SOURCE_LENGTH = 200
MAX_NOTES_LENGTH = 2000


class IndicatorType(StrEnum):
    """The kind of intelligence value an :class:`Indicator` carries.

    A fixed, closed set — deliberately not the same enum as the Universal
    Entity Detection Engine's ``EntityType``
    (:class:`~threatlens.entities.types.EntityType`). That engine
    *classifies* freeform search input, producing a type with a confidence
    and a validation status; an ``Indicator`` is always already typed by the
    analyst (or by whatever upstream Workspace/Case data it was drawn from)
    at the moment it is added, so no classification ever happens here. The
    two enums are intentionally independent and are not interchangeable.
    """

    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    HOSTNAME = "hostname"
    URL = "url"
    EMAIL = "email"
    SHA1 = "sha1"
    SHA256 = "sha256"
    MD5 = "md5"
    CVE = "cve"
    MITRE_TECHNIQUE = "mitre_technique"
    MITRE_SOFTWARE = "mitre_software"
    MITRE_GROUP = "mitre_group"
    REGISTRY = "registry"
    MUTEX = "mutex"
    FILENAME = "filename"
    PROCESS = "process"
    CERTIFICATE = "certificate"


class CollectionSource(StrEnum):
    """How a collection originated. Set once at creation; never changed after.

    Purely descriptive provenance — choosing ``WORKSPACE`` or ``CASE`` does
    not itself pull in any data. "Do NOT automatically extract intelligence.
    Extraction will come later" (phase brief); an analyst who builds a
    collection while looking at an investigation or a case still adds every
    indicator explicitly.
    """

    MANUAL = "manual"
    WORKSPACE = "workspace"
    CASE = "case"


class Indicator(BaseModel):
    """One piece of explicitly-provided threat intelligence.

    Identity for deduplication purposes is ``(type, normalized_value)`` —
    never ``value`` verbatim, and never a stored id: an ``Indicator`` has no
    id of its own and is addressed by identity rather than by a synthetic key
    (see :mod:`threatlens.collections.normalize`). Re-adding an indicator
    whose identity already exists in a collection merges into the existing
    record (see
    :meth:`~threatlens.collections.service.CollectionService.add_indicator`)
    rather than creating a duplicate or being rejected — unlike
    :class:`~threatlens.cases.models.CaseNote`, an ``Indicator`` legitimately
    changes over its lifetime as new sightings arrive, so it is not frozen.

    No field here is ever computed, enriched, or looked up — every value is
    exactly what the caller explicitly provided.
    """

    type: IndicatorType
    value: str = Field(min_length=1, max_length=MAX_VALUE_LENGTH)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    confidence: int | None = Field(default=None, ge=0, le=100)
    tags: list[str] = Field(default_factory=list)
    source: str | None = Field(default=None, max_length=MAX_SOURCE_LENGTH)
    notes: str | None = Field(default=None, max_length=MAX_NOTES_LENGTH)


class Collection(BaseModel):
    """A reusable, named set of threat intelligence.

    ``id`` is a randomly generated identifier (``uuid4``), matching the
    identity convention of every other operational record in ThreatLens
    (:class:`~threatlens.workspace.models.WorkspaceInvestigation`,
    :class:`~threatlens.cases.models.Case`) — two collections with identical
    content are two distinct records, never a collision.

    ``linked_workspace_ids``/``linked_case_ids`` hold only ids — never a copy
    of the referenced investigation's or case's content, exactly like
    :attr:`~threatlens.cases.models.Case.linked_workspace_ids`. Both
    relationships are many-to-many: nothing here enforces or assumes a
    one-to-one relationship, and neither Workspace nor Case Management has
    any notion of collections.

    ``indicators`` is the collection's actual intelligence payload,
    deduplicated by ``(type, normalized_value)`` — see
    :mod:`threatlens.collections.normalize`.

    ``metadata`` is a deliberately open, unopinionated extension point, the
    same role as :attr:`~threatlens.cases.models.Case.metadata`.
    """

    id: UUID
    name: str = Field(min_length=1, max_length=MAX_NAME_LENGTH)
    description: str | None = Field(default=None, max_length=MAX_DESCRIPTION_LENGTH)
    category: str | None = Field(default=None, max_length=MAX_CATEGORY_LENGTH)
    tags: list[str] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime
    source: CollectionSource = CollectionSource.MANUAL
    linked_case_ids: list[UUID] = Field(default_factory=list)
    linked_workspace_ids: list[UUID] = Field(default_factory=list)
    metadata: dict[str, JsonValue] = Field(default_factory=dict)
    indicators: list[Indicator] = Field(default_factory=list)
