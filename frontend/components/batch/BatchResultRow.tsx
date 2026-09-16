import { InvestigationWorkspace } from "@/components/InvestigationWorkspace";
import type { BatchRow } from "@/hooks/useBatchInvestigation";
import { detectionEligibility, providerCounts, riskLabel } from "@/lib/batch";

interface Props {
  row: BatchRow;
  index: number;
  expanded: boolean;
  running: boolean;
  timestamp: string;
  onSelect: (selected: boolean) => void;
  onRetry: () => void;
  onToggle: () => void;
}

export function BatchResultRow({ row, index, expanded, running, timestamp, onSelect, onRetry, onToggle }: Props) {
  const investigation = row.investigation;
  const summary = investigation?.investigation_summary;
  const counts = investigation ? providerCounts(investigation) : null;
  const quality = investigation ? detectionEligibility(investigation) : null;
  const stateColour = row.state === "completed" ? "bg-emerald-400" : row.state === "failed" ? "bg-red-400" : row.state === "running" ? "bg-sky-400 animate-pulse" : "bg-zinc-600";

  return (
    <article className="rounded-xl border border-zinc-800 bg-zinc-900/70 [content-visibility:auto]">
      <div className="flex flex-wrap items-center gap-3 p-4">
        <input aria-label={`Select ${row.entity.normalized_value}`} type="checkbox" checked={row.selected} disabled={row.state !== "completed"} onChange={(event) => onSelect(event.target.checked)} />
        <span className={`h-2.5 w-2.5 rounded-full ${stateColour}`} />
        <div className="min-w-48 flex-1"><p className="truncate font-mono text-sm text-zinc-100">{row.entity.normalized_value}</p><p className="text-xs uppercase text-zinc-500">{row.entity.type} · {row.state}</p></div>
        {summary && <div className="text-xs text-zinc-400">{riskLabel(summary.posture)} ({summary.posture}) · confidence {summary.overall_confidence.score} · {summary.findings.length} findings · {counts?.successful}/{counts?.failed} providers {investigation?.threat_intelligence.agreement?.conflicted && <span className="text-amber-300">· conflict</span>} · <span title={quality?.reason}>{quality?.eligible ? `eligible · ${quality.formats} formats` : "not eligible"}</span></div>}
        {row.error && <span className="text-xs text-red-300">{row.error}</span>}
        {row.retryable && !running && <button onClick={onRetry} className="rounded border border-zinc-700 px-2 py-1 text-xs">Retry</button>}
        {investigation && <button aria-expanded={expanded} aria-controls={`batch-detail-${index}`} onClick={onToggle} className="rounded px-2 py-1 text-zinc-400 focus-visible:outline focus-visible:outline-2 focus-visible:outline-sky-400">{expanded ? "Collapse" : "Expand"}</button>}
      </div>
      {expanded && investigation && <div id={`batch-detail-${index}`} className="border-t border-zinc-800 px-4 pb-4"><p className="pt-3 text-xs text-zinc-500">Detection quality: {quality?.reason} Generated rules show mapping, validation, review, and approval states; this is not live SIEM validation.</p><InvestigationWorkspace data={investigation} timestamp={timestamp} /></div>}
    </article>
  );
}
