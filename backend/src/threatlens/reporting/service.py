"""The Workspace Export & Investigation Reporting service (Phase 8.4).

Adapts a saved :class:`~threatlens.workspace.models.WorkspaceInvestigation`
into an :class:`~threatlens.reporting.models.InvestigationReport` by
composing the existing :class:`~threatlens.timeline.service.TimelineService`
and :class:`~threatlens.graph.service.GraphService` — never re-deriving what
either already computes, and never mutating the saved record or either
projection's output.
"""

from __future__ import annotations

from ..graph.service import GraphService
from ..timeline.service import TimelineService
from ..workspace.models import WorkspaceInvestigation
from .models import REPORTING_FRAMEWORK_VERSION, InvestigationReport


class ReportService:
    """Derives a read-only :class:`InvestigationReport` from one saved investigation."""

    def __init__(self, timeline_service: TimelineService, graph_service: GraphService) -> None:
        self._timeline = timeline_service
        self._graph = graph_service

    def build(self, record: WorkspaceInvestigation) -> InvestigationReport:
        """Build the report for ``record``.

        Delegates entirely to the injected ``TimelineService``/``GraphService``
        for their respective sections; this method's only job is composing
        their outputs with the saved record into one envelope.
        """
        return InvestigationReport(
            report_schema_version=REPORTING_FRAMEWORK_VERSION,
            investigation=record,
            timeline=self._timeline.build(record),
            graph=self._graph.build(record),
        )
