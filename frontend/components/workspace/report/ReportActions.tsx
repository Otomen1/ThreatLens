"use client";

// Report actions (Phase 8.4): Export JSON and Print Report. Both operate
// only on the already-fetched report data — no re-fetch, no server-side PDF
// generation. Hidden entirely when printing (`print:hidden`): these are
// interactive-only controls with no place on the printed page itself.

import type { InvestigationReport } from "@/lib/api";
import { sanitizeFilenameSegment, triggerJsonDownload } from "@/lib/download";

export function ReportActions({ report }: { report: InvestigationReport }) {
  function exportJson() {
    const filename = `threatlens-${sanitizeFilenameSegment(report.investigation.id)}.json`;
    triggerJsonDownload(filename, report);
  }

  return (
    <div className="print:hidden flex items-center justify-end gap-2">
      <button
        type="button"
        onClick={exportJson}
        className="text-xs font-medium text-zinc-300 hover:text-white bg-zinc-800 hover:bg-zinc-700 border border-zinc-700 rounded-lg px-3 py-1.5 transition-colors"
      >
        Export JSON
      </button>
      <button
        type="button"
        onClick={() => window.print()}
        className="text-xs font-medium text-white bg-sky-600 hover:bg-sky-500 rounded-lg px-3 py-1.5 transition-colors"
      >
        Print Report
      </button>
    </div>
  );
}
