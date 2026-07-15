"""Workspace Export & Investigation Reporting (Phase 8.4).

A pure, deterministic projection over a saved investigation's existing
outputs and existing derived projections — not a new intelligence engine,
not a fourth analytical pipeline, and not an AI-generated report. It bundles
the saved :class:`~threatlens.workspace.models.WorkspaceInvestigation`
verbatim with the exact same :class:`~threatlens.timeline.models.Timeline`
and :class:`~threatlens.graph.models.EvidenceGraph` that Phase 8.1's and
Phase 8.2's own endpoints already produce, so a JSON export and an analyst
report view can both be built from one deterministic call. Never invents a
finding, recommendation, correlation, relationship, or timestamp; never
calls an external provider or an AI model; never mutates the saved record.

There is no ``exceptions.py``: like Timeline (Phase 8.1) and Graph (Phase
8.2), a report is always derivable from a saved record — there is no
failure mode of this framework's own to name, only the existing "record not
found" case already handled at the API layer.
"""

from __future__ import annotations

from .models import REPORTING_FRAMEWORK_VERSION, InvestigationReport
from .service import ReportService

__all__ = [
    "REPORTING_FRAMEWORK_VERSION",
    "InvestigationReport",
    "ReportService",
]
