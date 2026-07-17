"""Intelligence Collections (Phase 9.1).

Reusable, analyst-curated sets of threat intelligence — "Silver Fox
Campaign", "APT29 Infrastructure", "Internal Blocklist" — built manually or
seeded from a Workspace investigation or a Case. Collections are NOT
analytical engines, NOT Cases, and NOT Workspaces: they are reusable
intelligence assets that reference (by id only, never by content copy) zero
or more :class:`~threatlens.workspace.models.WorkspaceInvestigation` records
and zero or more :class:`~threatlens.cases.models.Case` records. No AI, no
network, no automatic extraction — every indicator is exactly what an
analyst explicitly provided. Mirrors :mod:`threatlens.cases`'s own
architecture: models, a storage abstraction with one local-file-backed
implementation, a thin service, and an API — with no authentication
(single-user, self-hosted), per the phase brief.
"""

from __future__ import annotations

from .config import CollectionSettings
from .exceptions import (
    CollectionError,
    CollectionNotFoundError,
    CollectionStorageError,
)
from .models import (
    COLLECTION_FRAMEWORK_VERSION,
    Collection,
    CollectionSource,
    Indicator,
    IndicatorType,
)
from .normalize import normalize_indicator_value
from .schemas import (
    AddIndicatorRequest,
    CollectionListItem,
    CollectionListResponse,
    CreateCollectionRequest,
    LinkCaseRequest,
    LinkWorkspaceRequest,
    RemoveIndicatorRequest,
    UpdateCollectionRequest,
)
from .service import CollectionService
from .storage import CollectionStorage, LocalFileStorage

__all__ = [
    "COLLECTION_FRAMEWORK_VERSION",
    "AddIndicatorRequest",
    "Collection",
    "CollectionError",
    "CollectionListItem",
    "CollectionListResponse",
    "CollectionNotFoundError",
    "CollectionService",
    "CollectionSettings",
    "CollectionSource",
    "CollectionStorage",
    "CollectionStorageError",
    "CreateCollectionRequest",
    "Indicator",
    "IndicatorType",
    "LinkCaseRequest",
    "LinkWorkspaceRequest",
    "LocalFileStorage",
    "RemoveIndicatorRequest",
    "UpdateCollectionRequest",
    "normalize_indicator_value",
]
