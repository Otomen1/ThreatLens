"use client";

import Link from "next/link";
import { useState } from "react";

import { saveInvestigation, type Entity, type InvestigationSummary } from "@/lib/api";
import { entityLabel } from "@/lib/investigation";

interface Props {
  entity: Entity;
  investigationSummary: InvestigationSummary;
}

type State =
  | { kind: "idle" }
  | { kind: "saving" }
  | { kind: "saved"; id: string }
  | { kind: "error"; message: string };

/**
 * Persists the current, already-completed investigation into the Investigation
 * Workspace (Phase 8.0) — a separate save/load layer, not part of the search
 * pipeline. Attaches investigation_summary verbatim; nothing is recomputed.
 * Title/tags/status/severity can be refined afterward from the workspace
 * detail page — this button only needs one click to get a case saved.
 */
export function SaveInvestigationButton({ entity, investigationSummary }: Props) {
  const [state, setState] = useState<State>({ kind: "idle" });

  async function save() {
    setState({ kind: "saving" });
    try {
      const record = await saveInvestigation({
        title: `${entityLabel(entity.type)}: ${entity.value}`,
        investigation_type: entity.type,
        investigation_summary: investigationSummary,
      });
      setState({ kind: "saved", id: record.id });
    } catch (err) {
      setState({
        kind: "error",
        message: err instanceof Error ? err.message : "Could not save.",
      });
    }
  }

  if (state.kind === "saved") {
    return (
      <Link
        href={`/workspace/${state.id}`}
        className="shrink-0 inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-emerald-500/30 bg-emerald-500/10 text-emerald-300 text-xs font-medium hover:bg-emerald-500/20 transition-colors"
      >
        Saved · View in Workspace
      </Link>
    );
  }

  return (
    <div className="shrink-0 flex flex-col items-end gap-1">
      <button
        onClick={save}
        disabled={state.kind === "saving"}
        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-zinc-700 bg-zinc-800 text-zinc-300 text-xs font-medium hover:bg-zinc-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
      >
        {state.kind === "saving" ? "Saving…" : "Save to Workspace"}
      </button>
      {state.kind === "error" && (
        <span role="alert" className="text-[11px] text-red-400">
          {state.message}
        </span>
      )}
    </div>
  );
}
