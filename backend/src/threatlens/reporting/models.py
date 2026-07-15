"""Canonical model for Workspace Export & Investigation Reporting (Phase 8.4).

A pure, deterministic projection over one saved investigation's existing
outputs and existing derived projections — not a new intelligence engine,
not a fourth analytical pipeline. :class:`InvestigationReport` bundles the
saved :class:`~threatlens.workspace.models.WorkspaceInvestigation` verbatim
alongside the exact same :class:`~threatlens.timeline.models.Timeline` and
:class:`~threatlens.graph.models.EvidenceGraph` that Phase 8.1's and Phase
8.2's own endpoints already produce, so the JSON export and the analyst
report view are both built from one call, without duplicating either
projection's model or re-deriving anything it already computed.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from ..graph.models import EvidenceGraph
from ..timeline.models import Timeline
from ..workspace.models import WorkspaceInvestigation

REPORTING_FRAMEWORK_VERSION = "1.0"


class InvestigationReport(BaseModel):
    """Everything about one saved investigation, in one deterministic envelope.

    ``investigation`` is the saved record verbatim (its own metadata plus
    whichever engine outputs are attached); ``timeline``/``graph`` are the
    exact same objects ``GET .../timeline`` and ``GET .../graph`` already
    return. No field here is recomputed or renamed from either — this model
    adds only ``report_schema_version``, the one genuinely new piece of
    information: an explicit, independent version for this envelope's own
    shape, so a future change to the export contract (e.g. a new top-level
    section) doesn't need to be inferred from the engine versions nested
    inside it.

    Building this twice from the same saved record always yields a
    byte-identical ``InvestigationReport`` — ``timeline``/``graph`` are
    already proven deterministic by their own frameworks, and there is no
    wall-clock field of this envelope's own (deliberately: an ``exported_at``
    would only ever be request metadata, never part of the report's
    semantic identity, so none is included — see the architecture doc).
    """

    model_config = ConfigDict(frozen=True)

    report_schema_version: str = Field(min_length=1)
    investigation: WorkspaceInvestigation
    timeline: Timeline
    graph: EvidenceGraph
