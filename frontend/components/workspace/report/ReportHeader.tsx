// The analyst report's header (Phase 8.4): identity + provenance only —
// investigation id, title, entity, saved timestamp, and the report's own
// schema version. Every value is copied verbatim from the existing saved
// record; nothing here is generated.

import type { InvestigationReport } from "@/lib/api";
import { entityLabel } from "@/lib/investigation";

export function ReportHeader({ report }: { report: InvestigationReport }) {
  const { investigation } = report;

  return (
    <header className="border-b-2 border-zinc-800 print:border-zinc-400 pb-4 mb-2 print:break-inside-avoid">
      <div className="flex items-baseline justify-between gap-4 flex-wrap">
        <div>
          <p className="text-xs font-semibold tracking-widest uppercase text-sky-400 print:text-zinc-600">
            ThreatLens
          </p>
          <h1 className="text-2xl font-bold text-white print:text-black">Investigation Report</h1>
        </div>
        <span className="text-[11px] text-zinc-500 print:text-zinc-600">
          Report schema {report.report_schema_version}
        </span>
      </div>

      <h2 className="text-lg text-zinc-200 print:text-black mt-3 break-words">
        {investigation.title}
      </h2>

      <dl className="mt-2 grid grid-cols-2 sm:grid-cols-4 gap-x-4 gap-y-1.5 text-xs">
        <Field label="Investigation ID" value={investigation.id} mono />
        <Field label="Entity Type" value={entityLabel(investigation.investigation_type)} />
        <Field
          label="Entity Value"
          value={investigation.investigation_summary?.entity_value ?? "—"}
          mono
        />
        <Field label="Saved" value={new Date(investigation.updated_at).toLocaleString()} />
      </dl>
    </header>
  );
}

function Field({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="min-w-0">
      <dt className="text-[10px] uppercase tracking-wider text-zinc-500 print:text-zinc-600">
        {label}
      </dt>
      <dd
        className={`text-zinc-300 print:text-black break-words ${mono ? "font-mono text-[11px]" : ""}`}
      >
        {value}
      </dd>
    </div>
  );
}
