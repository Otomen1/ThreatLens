"""The Intelligence Collections service (Phase 9.1).

Pure plumbing over a :class:`~threatlens.collections.storage.CollectionStorage`
backend, plus the one piece of genuine business logic this subsystem owns:
deduplicating and merging indicators by ``(type, normalized_value)`` identity.
Everything else — linking a Workspace investigation or a Case, filtering — is
CRUD over caller-supplied data, exactly like
:class:`~threatlens.cases.service.CaseService`.

This service depends on
:class:`~threatlens.workspace.service.WorkspaceService` and
:class:`~threatlens.cases.service.CaseService` for exactly one thing each:
confirming a Workspace investigation or a Case exists before a collection
links to it. It never reads, mutates, or recomputes anything about either —
only their own ``get()``, the same read every other adjacent consumer uses.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

from ..cases.service import CaseService
from ..workspace.service import WorkspaceService
from .models import Collection, Indicator, IndicatorType
from .normalize import normalize_indicator_value
from .schemas import (
    AddIndicatorRequest,
    CreateCollectionRequest,
    RemoveIndicatorRequest,
    UpdateCollectionRequest,
)
from .storage import CollectionStorage


def _merge_indicator(existing: Indicator, incoming: Indicator) -> Indicator:
    """Merge ``incoming`` into ``existing`` (same ``(type, normalized_value)`` identity).

    ``first_seen``/``last_seen`` widen to the earliest/latest of the two;
    ``tags`` union (insertion order, deduped); ``confidence``/``source``/
    ``notes`` take the incoming value when provided, else keep the existing
    one. ``value`` (the raw, analyst-typed string) is left untouched — both
    forms are, by definition, the same normalized identity, so there is no
    principled reason to prefer one spelling over the other, and keeping the
    first-seen spelling avoids the display value jittering on every re-add.
    """
    first_seens = [t for t in (existing.first_seen, incoming.first_seen) if t is not None]
    last_seens = [t for t in (existing.last_seen, incoming.last_seen) if t is not None]
    merged_tags = list(existing.tags)
    for tag in incoming.tags:
        if tag not in merged_tags:
            merged_tags.append(tag)
    return existing.model_copy(
        update={
            "first_seen": min(first_seens) if first_seens else None,
            "last_seen": max(last_seens) if last_seens else None,
            "confidence": incoming.confidence
            if incoming.confidence is not None
            else existing.confidence,
            "tags": merged_tags,
            "source": incoming.source if incoming.source is not None else existing.source,
            "notes": incoming.notes if incoming.notes is not None else existing.notes,
        }
    )


def _find_by_identity(
    indicators: list[Indicator], indicator_type: IndicatorType, normalized: str
) -> int | None:
    for i, ind in enumerate(indicators):
        if (
            ind.type == indicator_type
            and normalize_indicator_value(ind.type, ind.value) == normalized
        ):
            return i
    return None


class CollectionService:
    """Orchestrates persistence, retrieval, filtering, indicators, and links."""

    def __init__(
        self,
        storage: CollectionStorage,
        workspace_service: WorkspaceService,
        case_service: CaseService,
    ) -> None:
        self._storage = storage
        self._workspace = workspace_service
        self._cases = case_service

    def create(
        self, request: CreateCollectionRequest, *, now: datetime | None = None
    ) -> Collection:
        """Persist a new collection; returns it with a fresh id.

        ``id`` is always a fresh ``uuid4()`` — creating two collections with
        identical content produces two distinct records, never a collision.
        """
        timestamp = now or datetime.now(UTC)
        collection = Collection(
            id=uuid4(),
            name=request.name,
            description=request.description,
            category=request.category,
            tags=request.tags,
            created_at=timestamp,
            updated_at=timestamp,
            source=request.source,
            metadata=request.metadata,
        )
        self._storage.save(collection)
        return collection

    def get(self, collection_id: UUID) -> Collection:
        """Return one collection.

        Raises :class:`~threatlens.collections.exceptions.CollectionNotFoundError`
        if no record exists with that id.
        """
        return self._storage.load(collection_id)

    def update(
        self, collection_id: UUID, request: UpdateCollectionRequest, *, now: datetime | None = None
    ) -> Collection:
        """Apply a partial update; only fields explicitly set on ``request`` change.

        Raises :class:`~threatlens.collections.exceptions.CollectionNotFoundError`
        if no record exists with that id.
        """
        existing = self._storage.load(collection_id)
        changes = request.model_dump(exclude_unset=True)
        # `tags`/`metadata` are non-optional collections on `Collection` itself
        # (unlike `description`/`category`, which are genuinely `X | None`);
        # `model_copy` does not re-validate, so an explicit `null` for either
        # must be normalized to its empty form here rather than ever writing
        # a bare `None` into a field typed as `list`/`dict` — same fix as
        # `CaseService.update`.
        if changes.get("tags") is None and "tags" in changes:
            changes["tags"] = []
        if changes.get("metadata") is None and "metadata" in changes:
            changes["metadata"] = {}
        changes["updated_at"] = now or datetime.now(UTC)
        updated = existing.model_copy(update=changes)
        self._storage.save(updated)
        return updated

    def delete(self, collection_id: UUID) -> None:
        """Remove a collection.

        Raises :class:`~threatlens.collections.exceptions.CollectionNotFoundError`
        if no record exists with that id.
        """
        self._storage.delete(collection_id)

    def list(
        self,
        *,
        name: str | None = None,
        category: str | None = None,
        indicator_type: IndicatorType | None = None,
        tag: str | None = None,
        linked_case_id: UUID | None = None,
        linked_workspace_id: UUID | None = None,
    ) -> list[Collection]:
        """Every collection matching all given filters, most recently updated first.

        With no filters given, this is a plain, unfiltered enumeration —
        backing both ``GET /api/v1/collections`` (browse) and
        ``GET /api/v1/collections/search`` (filtered) with one implementation.
        Filtering is a pure in-memory operation over already-persisted
        records — never a database query, never full-text indexing, never AI.
        ``name`` is a case-insensitive substring match, mirroring
        :class:`~threatlens.cases.service.CaseService`'s own ``title`` search.
        """
        records = self._storage.list_all()
        if name:
            needle = name.lower()
            records = [c for c in records if needle in c.name.lower()]
        if category is not None:
            records = [c for c in records if c.category == category]
        if indicator_type is not None:
            records = [c for c in records if any(i.type == indicator_type for i in c.indicators)]
        if tag is not None:
            records = [c for c in records if tag in c.tags]
        if linked_case_id is not None:
            records = [c for c in records if linked_case_id in c.linked_case_ids]
        if linked_workspace_id is not None:
            records = [c for c in records if linked_workspace_id in c.linked_workspace_ids]
        return sorted(records, key=lambda c: c.updated_at, reverse=True)

    def add_indicator(
        self, collection_id: UUID, request: AddIndicatorRequest, *, now: datetime | None = None
    ) -> Collection:
        """Add one indicator to a collection.

        Deduplicated by ``(type, normalized_value)``: if an indicator with
        the same identity already exists, the two are merged (see
        :func:`_merge_indicator`) rather than creating a duplicate.
        """
        existing = self._storage.load(collection_id)
        normalized = normalize_indicator_value(request.type, request.value)
        incoming = Indicator(
            type=request.type,
            value=request.value,
            first_seen=request.first_seen,
            last_seen=request.last_seen,
            confidence=request.confidence,
            tags=request.tags,
            source=request.source,
            notes=request.notes,
        )
        match_index = _find_by_identity(existing.indicators, request.type, normalized)
        if match_index is None:
            indicators = [*existing.indicators, incoming]
        else:
            indicators = list(existing.indicators)
            indicators[match_index] = _merge_indicator(indicators[match_index], incoming)
        updated = existing.model_copy(
            update={"indicators": indicators, "updated_at": now or datetime.now(UTC)}
        )
        self._storage.save(updated)
        return updated

    def remove_indicator(
        self, collection_id: UUID, request: RemoveIndicatorRequest, *, now: datetime | None = None
    ) -> Collection:
        """Remove one indicator from a collection, matched by ``(type, normalized_value)``.

        Idempotent: removing an identity that isn't present is a no-op and
        leaves ``updated_at`` unchanged, matching
        :meth:`~threatlens.cases.service.CaseService.unlink_workspace`.
        """
        existing = self._storage.load(collection_id)
        normalized = normalize_indicator_value(request.type, request.value)
        remaining = [
            ind
            for ind in existing.indicators
            if not (
                ind.type == request.type
                and normalize_indicator_value(ind.type, ind.value) == normalized
            )
        ]
        if len(remaining) == len(existing.indicators):
            return existing
        updated = existing.model_copy(
            update={"indicators": remaining, "updated_at": now or datetime.now(UTC)}
        )
        self._storage.save(updated)
        return updated

    def link_workspace(
        self, collection_id: UUID, workspace_id: UUID, *, now: datetime | None = None
    ) -> Collection:
        """Link one Workspace investigation to a collection.

        Confirms the investigation exists via ``WorkspaceService.get()``
        (raising
        :class:`~threatlens.workspace.exceptions.InvestigationNotFoundError`
        if not) before linking, so a collection can never reference a
        nonexistent investigation. Idempotent: linking an already-linked id
        is a no-op and leaves ``updated_at`` unchanged.
        """
        self._workspace.get(workspace_id)
        existing = self._storage.load(collection_id)
        if workspace_id in existing.linked_workspace_ids:
            return existing
        updated = existing.model_copy(
            update={
                "linked_workspace_ids": [*existing.linked_workspace_ids, workspace_id],
                "updated_at": now or datetime.now(UTC),
            }
        )
        self._storage.save(updated)
        return updated

    def link_case(
        self, collection_id: UUID, case_id: UUID, *, now: datetime | None = None
    ) -> Collection:
        """Link one Case to a collection.

        Confirms the case exists via ``CaseService.get()`` (raising
        :class:`~threatlens.cases.exceptions.CaseNotFoundError` if not)
        before linking. Idempotent: linking an already-linked id is a no-op
        and leaves ``updated_at`` unchanged.
        """
        self._cases.get(case_id)
        existing = self._storage.load(collection_id)
        if case_id in existing.linked_case_ids:
            return existing
        updated = existing.model_copy(
            update={
                "linked_case_ids": [*existing.linked_case_ids, case_id],
                "updated_at": now or datetime.now(UTC),
            }
        )
        self._storage.save(updated)
        return updated
