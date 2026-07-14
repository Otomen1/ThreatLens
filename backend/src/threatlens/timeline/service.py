"""The Investigation Timeline service (Phase 8.1).

Adapts a saved :class:`~threatlens.workspace.models.WorkspaceInvestigation`
into a :class:`~threatlens.timeline.models.Timeline`. All evidence-derivation
logic lives in :mod:`~threatlens.timeline.engine`; this module owns only
"which field of a saved record feeds which part of the timeline" — no
investigation logic, no reasoning, no correlation, no persistence, no
mutation of the saved record.
"""

from __future__ import annotations

from ..workspace.models import WorkspaceInvestigation
from .engine import collect_events
from .models import Timeline


class TimelineService:
    """Derives a read-only :class:`Timeline` from one saved investigation."""

    def build(self, record: WorkspaceInvestigation) -> Timeline:
        """Build the timeline for ``record``.

        When ``record.investigation_summary`` is absent (a saved case with
        no attached reasoning output), the result is a well-formed, empty
        timeline — not an error — using the record's own ``investigation_type``
        and ``updated_at`` for context, since there is no
        ``InvestigationSummary`` to supply an ``entity_value`` or a
        ``generated_at``.
        """
        summary = record.investigation_summary
        if summary is None:
            return Timeline(
                investigation_id=record.id,
                entity_type=record.investigation_type,
                entity_value="",
                generated_at=record.updated_at,
                events=(),
            )
        return Timeline(
            investigation_id=record.id,
            entity_type=summary.entity_type,
            entity_value=summary.entity_value,
            generated_at=summary.generated_at,
            events=collect_events(summary),
        )
