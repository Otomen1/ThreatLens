"use client";

import Link from "next/link";
import { useCallback, useEffect, useRef, useState } from "react";

import {
  deleteInvestigation,
  listInvestigations,
  type WorkspaceListItem,
  type WorkspaceStatus,
} from "@/lib/api";
import { entityLabel, severityClasses, severityLabel } from "@/lib/investigation";

type State =
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "ready"; items: WorkspaceListItem[] };

const STATUS_OPTIONS: { value: WorkspaceStatus | ""; label: string }[] = [
  { value: "", label: "All statuses" },
  { value: "open", label: "Open" },
  { value: "in_progress", label: "In Progress" },
  { value: "closed", label: "Closed" },
  { value: "archived", label: "Archived" },
];

const SEVERITY_OPTIONS = [
  { value: "", label: "All severities" },
  { value: "4", label: "Critical" },
  { value: "3", label: "High" },
  { value: "2", label: "Medium" },
  { value: "1", label: "Low" },
  { value: "0", label: "Informational" },
];

export default function WorkspacePage() {
  const [state, setState] = useState<State>({ kind: "loading" });
  const [query, setQuery] = useState("");
  const [status, setStatus] = useState<WorkspaceStatus | "">("");
  const [severity, setSeverity] = useState("");
  const abortRef = useRef<AbortController | null>(null);

  const load = useCallback(async () => {
    abortRef.current?.abort();
    const controller = new AbortController();
    abortRef.current = controller;
    setState({ kind: "loading" });
    try {
      const res = await listInvestigations(
        {
          q: query.trim() || undefined,
          status: status || undefined,
          severity: severity === "" ? undefined : Number(severity),
        },
        controller.signal,
      );
      setState({ kind: "ready", items: res.investigations });
    } catch (err) {
      if (err instanceof DOMException && err.name === "AbortError") return;
      setState({
        kind: "error",
        message: err instanceof Error ? err.message : "Could not reach the service.",
      });
    }
  }, [query, status, severity]);

  useEffect(() => {
    load();
    return () => abortRef.current?.abort();
  }, [load]);

  async function handleDelete(id: string) {
    if (!confirm("Delete this saved investigation? This cannot be undone.")) return;
    try {
      await deleteInvestigation(id);
      setState((prev) =>
        prev.kind === "ready"
          ? { kind: "ready", items: prev.items.filter((item) => item.id !== id) }
          : prev,
      );
    } catch {
      // A failed delete just leaves the row in place; the user can retry.
    }
  }

  return (
    <main className="min-h-screen px-4 py-10 sm:py-14">
      <div className="w-full max-w-4xl mx-auto space-y-6">
        <header>
          <Link href="/" className="text-xs text-zinc-500 hover:text-zinc-300 transition-colors">
            ← Back to Search
          </Link>
          <h1 className="text-2xl font-semibold text-white tracking-tight mt-1">
            Investigation Workspace
          </h1>
          <p className="text-zinc-500 text-sm mt-1">
            Saved investigations — stored locally, searchable, and filterable. Nothing here is
            recomputed; every record is a snapshot of a completed investigation.
          </p>
        </header>

        <div className="flex flex-wrap gap-2">
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && load()}
            placeholder="Search title, summary, tags…"
            aria-label="Search saved investigations"
            className="flex-1 min-w-[180px] bg-zinc-900 border border-zinc-800 rounded-xl px-3 py-2 text-sm text-white placeholder-zinc-600 focus:outline-none focus:border-zinc-600"
          />
          <select
            value={status}
            onChange={(e) => setStatus(e.target.value as WorkspaceStatus | "")}
            aria-label="Filter by status"
            className="bg-zinc-900 border border-zinc-800 rounded-xl px-3 py-2 text-sm text-zinc-300 focus:outline-none focus:border-zinc-600"
          >
            {STATUS_OPTIONS.map((opt) => (
              <option key={opt.value} value={opt.value}>
                {opt.label}
              </option>
            ))}
          </select>
          <select
            value={severity}
            onChange={(e) => setSeverity(e.target.value)}
            aria-label="Filter by severity"
            className="bg-zinc-900 border border-zinc-800 rounded-xl px-3 py-2 text-sm text-zinc-300 focus:outline-none focus:border-zinc-600"
          >
            {SEVERITY_OPTIONS.map((opt) => (
              <option key={opt.value} value={opt.value}>
                {opt.label}
              </option>
            ))}
          </select>
        </div>

        {state.kind === "loading" && (
          <div className="bg-zinc-900 border border-zinc-800 rounded-2xl p-8 text-center text-sm text-zinc-500">
            Loading saved investigations…
          </div>
        )}

        {state.kind === "error" && (
          <div
            role="alert"
            className="bg-red-500/10 border border-red-500/30 text-red-300 text-sm rounded-xl px-4 py-3"
          >
            {state.message}
          </div>
        )}

        {state.kind === "ready" && state.items.length === 0 && (
          <div className="bg-zinc-900 border border-zinc-800 rounded-2xl p-8 text-center text-sm text-zinc-500">
            No saved investigations yet. Run a search and use “Save to Workspace”.
          </div>
        )}

        {state.kind === "ready" && state.items.length > 0 && (
          <ul className="space-y-2">
            {state.items.map((item) => (
              <InvestigationRow
                key={item.id}
                item={item}
                onDelete={() => handleDelete(item.id)}
              />
            ))}
          </ul>
        )}
      </div>
    </main>
  );
}

function InvestigationRow({
  item,
  onDelete,
}: {
  item: WorkspaceListItem;
  onDelete: () => void;
}) {
  return (
    <li className="bg-zinc-900 border border-zinc-800 rounded-2xl p-4 flex items-center gap-3">
      <Link href={`/workspace/${item.id}`} className="flex-1 min-w-0 group">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-sm text-white group-hover:underline truncate">{item.title}</span>
          <StatusBadge status={item.status} />
          {item.severity !== null && (
            <span
              className={`text-[10px] px-2 py-0.5 rounded-full border ${severityClasses(item.severity)}`}
            >
              {severityLabel(item.severity)}
            </span>
          )}
        </div>
        <div className="flex items-center gap-2 mt-1 flex-wrap">
          <span className="text-[11px] text-zinc-500">{entityLabel(item.investigation_type)}</span>
          <span className="text-zinc-700">·</span>
          <span className="text-[11px] text-zinc-600">
            Updated {new Date(item.updated_at).toLocaleDateString()}
          </span>
          {item.tags.length > 0 && (
            <>
              <span className="text-zinc-700">·</span>
              {item.tags.slice(0, 4).map((tag) => (
                <span
                  key={tag}
                  className="text-[10px] text-zinc-400 bg-zinc-800 rounded-full px-2 py-0.5"
                >
                  {tag}
                </span>
              ))}
            </>
          )}
        </div>
      </Link>
      <button
        onClick={onDelete}
        aria-label={`Delete ${item.title}`}
        className="shrink-0 text-xs text-zinc-500 hover:text-red-400 transition-colors px-2 py-1"
      >
        Delete
      </button>
    </li>
  );
}

function StatusBadge({ status }: { status: WorkspaceStatus }) {
  const labels: Record<WorkspaceStatus, string> = {
    open: "Open",
    in_progress: "In Progress",
    closed: "Closed",
    archived: "Archived",
  };
  const classes: Record<WorkspaceStatus, string> = {
    open: "text-blue-400 bg-blue-500/10 border-blue-500/30",
    in_progress: "text-amber-400 bg-amber-500/10 border-amber-500/30",
    closed: "text-emerald-400 bg-emerald-500/10 border-emerald-500/30",
    archived: "text-zinc-400 bg-zinc-700/20 border-zinc-600/40",
  };
  return (
    <span className={`text-[10px] px-2 py-0.5 rounded-full border ${classes[status]}`}>
      {labels[status]}
    </span>
  );
}
