"use client";

import Link from "next/link";
import { useCallback, useEffect, useRef, useState } from "react";

import {
  createCase,
  listCases,
  type Case,
  type CasePriority,
  type CaseStatus,
} from "@/lib/api";

type State =
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "ready"; items: Case[] };

const STATUS_OPTIONS: { value: CaseStatus | ""; label: string }[] = [
  { value: "", label: "All statuses" },
  { value: "open", label: "Open" },
  { value: "in_progress", label: "In Progress" },
  { value: "resolved", label: "Resolved" },
  { value: "closed", label: "Closed" },
];

const PRIORITY_OPTIONS: { value: CasePriority | ""; label: string }[] = [
  { value: "", label: "All priorities" },
  { value: "critical", label: "Critical" },
  { value: "high", label: "High" },
  { value: "medium", label: "Medium" },
  { value: "low", label: "Low" },
];

export default function CasesPage() {
  const [state, setState] = useState<State>({ kind: "loading" });
  const [title, setTitle] = useState("");
  const [status, setStatus] = useState<CaseStatus | "">("");
  const [priority, setPriority] = useState<CasePriority | "">("");
  const [owner, setOwner] = useState("");
  const [tag, setTag] = useState("");
  const [creating, setCreating] = useState(false);
  const abortRef = useRef<AbortController | null>(null);

  const load = useCallback(async () => {
    abortRef.current?.abort();
    const controller = new AbortController();
    abortRef.current = controller;
    setState({ kind: "loading" });
    try {
      const res = await listCases(
        {
          title: title.trim() || undefined,
          status: status || undefined,
          priority: priority || undefined,
          owner: owner.trim() || undefined,
          tag: tag.trim() || undefined,
        },
        controller.signal,
      );
      setState({ kind: "ready", items: res.cases });
    } catch (err) {
      if (err instanceof DOMException && err.name === "AbortError") return;
      setState({
        kind: "error",
        message: err instanceof Error ? err.message : "Could not reach the service.",
      });
    }
  }, [title, status, priority, owner, tag]);

  useEffect(() => {
    load();
    return () => abortRef.current?.abort();
  }, [load]);

  return (
    <main className="min-h-screen px-4 py-10 sm:py-14">
      <div className="w-full max-w-4xl mx-auto space-y-6">
        <header>
          <Link href="/" className="text-xs text-zinc-500 hover:text-zinc-300 transition-colors">
            ← Back to Search
          </Link>
          <h1 className="text-2xl font-semibold text-white tracking-tight mt-1">
            Case Management
          </h1>
          <p className="text-zinc-500 text-sm mt-1">
            Operational cases that organize saved Workspace investigations by reference. A case
            never duplicates an investigation's content.
          </p>
        </header>

        <NewCaseForm
          creating={creating}
          onCreate={async (request) => {
            setCreating(true);
            try {
              await createCase(request);
              await load();
            } finally {
              setCreating(false);
            }
          }}
        />

        <div className="flex flex-wrap gap-2">
          <input
            type="text"
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && load()}
            placeholder="Search title…"
            aria-label="Search case titles"
            className="flex-1 min-w-[160px] bg-zinc-900 border border-zinc-800 rounded-xl px-3 py-2 text-sm text-white placeholder-zinc-600 focus:outline-none focus:border-zinc-600"
          />
          <select
            value={status}
            onChange={(e) => setStatus(e.target.value as CaseStatus | "")}
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
            value={priority}
            onChange={(e) => setPriority(e.target.value as CasePriority | "")}
            aria-label="Filter by priority"
            className="bg-zinc-900 border border-zinc-800 rounded-xl px-3 py-2 text-sm text-zinc-300 focus:outline-none focus:border-zinc-600"
          >
            {PRIORITY_OPTIONS.map((opt) => (
              <option key={opt.value} value={opt.value}>
                {opt.label}
              </option>
            ))}
          </select>
          <input
            type="text"
            value={owner}
            onChange={(e) => setOwner(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && load()}
            placeholder="Owner…"
            aria-label="Filter by owner"
            className="w-32 bg-zinc-900 border border-zinc-800 rounded-xl px-3 py-2 text-sm text-white placeholder-zinc-600 focus:outline-none focus:border-zinc-600"
          />
          <input
            type="text"
            value={tag}
            onChange={(e) => setTag(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && load()}
            placeholder="Tag…"
            aria-label="Filter by tag"
            className="w-28 bg-zinc-900 border border-zinc-800 rounded-xl px-3 py-2 text-sm text-white placeholder-zinc-600 focus:outline-none focus:border-zinc-600"
          />
        </div>

        {state.kind === "loading" && (
          <div className="bg-zinc-900 border border-zinc-800 rounded-2xl p-8 text-center text-sm text-zinc-500">
            Loading cases…
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
            No cases yet. Create one above.
          </div>
        )}

        {state.kind === "ready" && state.items.length > 0 && (
          <ul className="space-y-2">
            {state.items.map((item) => (
              <CaseRow key={item.id} item={item} />
            ))}
          </ul>
        )}
      </div>
    </main>
  );
}

function NewCaseForm({
  creating,
  onCreate,
}: {
  creating: boolean;
  onCreate: (request: { title: string; priority: CasePriority; owner?: string }) => Promise<void>;
}) {
  const [open, setOpen] = useState(false);
  const [title, setTitle] = useState("");
  const [priority, setPriority] = useState<CasePriority>("medium");
  const [owner, setOwner] = useState("");

  async function submit() {
    if (!title.trim()) return;
    await onCreate({ title: title.trim(), priority, owner: owner.trim() || undefined });
    setTitle("");
    setOwner("");
    setPriority("medium");
    setOpen(false);
  }

  if (!open) {
    return (
      <button
        onClick={() => setOpen(true)}
        className="text-xs font-medium text-zinc-300 hover:text-white bg-zinc-900 hover:bg-zinc-800 border border-zinc-800 rounded-xl px-4 py-2 transition-colors"
      >
        + New Case
      </button>
    );
  }

  return (
    <div className="bg-zinc-900 border border-zinc-800 rounded-2xl p-4 space-y-3">
      <input
        type="text"
        value={title}
        onChange={(e) => setTitle(e.target.value)}
        placeholder="Case title"
        aria-label="New case title"
        autoFocus
        className="w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 text-sm text-white placeholder-zinc-600 focus:outline-none focus:border-zinc-600"
      />
      <div className="flex flex-wrap gap-2">
        <select
          value={priority}
          onChange={(e) => setPriority(e.target.value as CasePriority)}
          aria-label="New case priority"
          className="bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 text-sm text-zinc-300 focus:outline-none"
        >
          <option value="low">Low</option>
          <option value="medium">Medium</option>
          <option value="high">High</option>
          <option value="critical">Critical</option>
        </select>
        <input
          type="text"
          value={owner}
          onChange={(e) => setOwner(e.target.value)}
          placeholder="Owner (optional)"
          aria-label="New case owner"
          className="flex-1 min-w-[140px] bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 text-sm text-white placeholder-zinc-600 focus:outline-none focus:border-zinc-600"
        />
      </div>
      <div className="flex items-center gap-2">
        <button
          onClick={submit}
          disabled={creating || !title.trim()}
          className="text-xs font-medium text-white bg-zinc-700 hover:bg-zinc-600 disabled:opacity-40 disabled:cursor-not-allowed rounded-lg px-3 py-1.5 transition-colors"
        >
          {creating ? "Creating…" : "Create"}
        </button>
        <button
          onClick={() => setOpen(false)}
          className="text-xs text-zinc-500 hover:text-zinc-300 transition-colors"
        >
          Cancel
        </button>
      </div>
    </div>
  );
}

function CaseRow({ item }: { item: Case }) {
  return (
    <li className="bg-zinc-900 border border-zinc-800 rounded-2xl p-4">
      <Link href={`/cases/${item.id}`} className="block group">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-sm text-white group-hover:underline truncate">{item.title}</span>
          <StatusBadge status={item.status} />
          <PriorityBadge priority={item.priority} />
        </div>
        <div className="flex items-center gap-2 mt-1 flex-wrap">
          {item.owner && <span className="text-[11px] text-zinc-500">{item.owner}</span>}
          {item.owner && <span className="text-zinc-700">·</span>}
          <span className="text-[11px] text-zinc-600">
            Updated {new Date(item.updated_at).toLocaleDateString()}
          </span>
          <span className="text-zinc-700">·</span>
          <span className="text-[11px] text-zinc-600">
            {item.linked_workspace_ids.length} linked
          </span>
          <span className="text-zinc-700">·</span>
          <span className="text-[11px] text-zinc-600">{item.notes.length} notes</span>
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
    </li>
  );
}

export function StatusBadge({ status }: { status: CaseStatus }) {
  const labels: Record<CaseStatus, string> = {
    open: "Open",
    in_progress: "In Progress",
    resolved: "Resolved",
    closed: "Closed",
  };
  const classes: Record<CaseStatus, string> = {
    open: "text-blue-400 bg-blue-500/10 border-blue-500/30",
    in_progress: "text-amber-400 bg-amber-500/10 border-amber-500/30",
    resolved: "text-emerald-400 bg-emerald-500/10 border-emerald-500/30",
    closed: "text-zinc-400 bg-zinc-700/20 border-zinc-600/40",
  };
  return (
    <span className={`text-[10px] px-2 py-0.5 rounded-full border ${classes[status]}`}>
      {labels[status]}
    </span>
  );
}

export function PriorityBadge({ priority }: { priority: CasePriority }) {
  const labels: Record<CasePriority, string> = {
    low: "Low",
    medium: "Medium",
    high: "High",
    critical: "Critical",
  };
  const classes: Record<CasePriority, string> = {
    low: "text-zinc-400 bg-zinc-700/20 border-zinc-600/40",
    medium: "text-blue-400 bg-blue-500/10 border-blue-500/30",
    high: "text-orange-400 bg-orange-500/10 border-orange-500/30",
    critical: "text-red-400 bg-red-500/10 border-red-500/30",
  };
  return (
    <span className={`text-[10px] px-2 py-0.5 rounded-full border ${classes[priority]}`}>
      {labels[priority]}
    </span>
  );
}
