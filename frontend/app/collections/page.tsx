"use client";

import Link from "next/link";
import { useCallback, useEffect, useRef, useState } from "react";

import {
  createCollection,
  listCollections,
  searchCollections,
  type CollectionListFilters,
  type CollectionListItem,
  type CollectionSource,
  type IndicatorType,
} from "@/lib/api";

type State =
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "ready"; items: CollectionListItem[] };

const SOURCE_OPTIONS: { value: CollectionSource; label: string }[] = [
  { value: "manual", label: "Manual" },
  { value: "workspace", label: "From Workspace" },
  { value: "case", label: "From Case" },
];

const INDICATOR_TYPE_OPTIONS: { value: IndicatorType | ""; label: string }[] = [
  { value: "", label: "All indicator types" },
  { value: "ipv4", label: "IPv4" },
  { value: "ipv6", label: "IPv6" },
  { value: "domain", label: "Domain" },
  { value: "hostname", label: "Hostname" },
  { value: "url", label: "URL" },
  { value: "email", label: "Email" },
  { value: "sha1", label: "SHA1" },
  { value: "sha256", label: "SHA256" },
  { value: "md5", label: "MD5" },
  { value: "cve", label: "CVE" },
  { value: "mitre_technique", label: "MITRE Technique" },
  { value: "mitre_software", label: "MITRE Software" },
  { value: "mitre_group", label: "MITRE Group" },
  { value: "registry", label: "Registry" },
  { value: "mutex", label: "Mutex" },
  { value: "filename", label: "Filename" },
  { value: "process", label: "Process" },
  { value: "certificate", label: "Certificate" },
];

export default function CollectionsPage() {
  const [state, setState] = useState<State>({ kind: "loading" });
  const [name, setName] = useState("");
  const [category, setCategory] = useState("");
  const [indicatorType, setIndicatorType] = useState<IndicatorType | "">("");
  const [tag, setTag] = useState("");
  const [creating, setCreating] = useState(false);
  const abortRef = useRef<AbortController | null>(null);

  const load = useCallback(async () => {
    abortRef.current?.abort();
    const controller = new AbortController();
    abortRef.current = controller;
    setState({ kind: "loading" });
    const filters: CollectionListFilters = {
      name: name.trim() || undefined,
      category: category.trim() || undefined,
      indicator_type: indicatorType || undefined,
      tag: tag.trim() || undefined,
    };
    const hasFilter = Object.values(filters).some((v) => v !== undefined);
    try {
      const res = hasFilter
        ? await searchCollections(filters, controller.signal)
        : await listCollections(controller.signal);
      setState({ kind: "ready", items: res.collections });
    } catch (err) {
      if (err instanceof DOMException && err.name === "AbortError") return;
      setState({
        kind: "error",
        message: err instanceof Error ? err.message : "Could not reach the service.",
      });
    }
  }, [name, category, indicatorType, tag]);

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
            Intelligence Collections
          </h1>
          <p className="text-zinc-500 text-sm mt-1">
            Reusable, analyst-curated sets of threat intelligence. Collections reference —
            never duplicate — Workspace investigations and Cases.
          </p>
        </header>

        <NewCollectionForm
          creating={creating}
          onCreate={async (request) => {
            setCreating(true);
            try {
              await createCollection(request);
              await load();
            } finally {
              setCreating(false);
            }
          }}
        />

        <div className="flex flex-wrap gap-2">
          <input
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && load()}
            placeholder="Search name…"
            aria-label="Search collection names"
            className="flex-1 min-w-[160px] bg-zinc-900 border border-zinc-800 rounded-xl px-3 py-2 text-sm text-white placeholder-zinc-600 focus:outline-none focus:border-zinc-600"
          />
          <input
            type="text"
            value={category}
            onChange={(e) => setCategory(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && load()}
            placeholder="Category…"
            aria-label="Filter by category"
            className="w-32 bg-zinc-900 border border-zinc-800 rounded-xl px-3 py-2 text-sm text-white placeholder-zinc-600 focus:outline-none focus:border-zinc-600"
          />
          <select
            value={indicatorType}
            onChange={(e) => setIndicatorType(e.target.value as IndicatorType | "")}
            aria-label="Filter by indicator type"
            className="bg-zinc-900 border border-zinc-800 rounded-xl px-3 py-2 text-sm text-zinc-300 focus:outline-none focus:border-zinc-600"
          >
            {INDICATOR_TYPE_OPTIONS.map((opt) => (
              <option key={opt.value} value={opt.value}>
                {opt.label}
              </option>
            ))}
          </select>
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
            Loading collections…
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
            No collections yet. Create one above.
          </div>
        )}

        {state.kind === "ready" && state.items.length > 0 && (
          <ul className="space-y-2">
            {state.items.map((item) => (
              <CollectionRow key={item.id} item={item} />
            ))}
          </ul>
        )}
      </div>
    </main>
  );
}

function NewCollectionForm({
  creating,
  onCreate,
}: {
  creating: boolean;
  onCreate: (request: {
    name: string;
    category?: string;
    source: CollectionSource;
  }) => Promise<void>;
}) {
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [category, setCategory] = useState("");
  const [source, setSource] = useState<CollectionSource>("manual");

  async function submit() {
    if (!name.trim()) return;
    await onCreate({ name: name.trim(), category: category.trim() || undefined, source });
    setName("");
    setCategory("");
    setSource("manual");
    setOpen(false);
  }

  if (!open) {
    return (
      <button
        onClick={() => setOpen(true)}
        className="text-xs font-medium text-zinc-300 hover:text-white bg-zinc-900 hover:bg-zinc-800 border border-zinc-800 rounded-xl px-4 py-2 transition-colors"
      >
        + New Collection
      </button>
    );
  }

  return (
    <div className="bg-zinc-900 border border-zinc-800 rounded-2xl p-4 space-y-3">
      <input
        type="text"
        value={name}
        onChange={(e) => setName(e.target.value)}
        placeholder="Collection name (e.g. Silver Fox Campaign)"
        aria-label="New collection name"
        autoFocus
        className="w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 text-sm text-white placeholder-zinc-600 focus:outline-none focus:border-zinc-600"
      />
      <div className="flex flex-wrap gap-2">
        <input
          type="text"
          value={category}
          onChange={(e) => setCategory(e.target.value)}
          placeholder="Category (optional)"
          aria-label="New collection category"
          className="flex-1 min-w-[140px] bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 text-sm text-white placeholder-zinc-600 focus:outline-none focus:border-zinc-600"
        />
        <select
          value={source}
          onChange={(e) => setSource(e.target.value as CollectionSource)}
          aria-label="New collection source"
          className="bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 text-sm text-zinc-300 focus:outline-none"
        >
          {SOURCE_OPTIONS.map((opt) => (
            <option key={opt.value} value={opt.value}>
              {opt.label}
            </option>
          ))}
        </select>
      </div>
      <div className="flex items-center gap-2">
        <button
          onClick={submit}
          disabled={creating || !name.trim()}
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

function CollectionRow({ item }: { item: CollectionListItem }) {
  return (
    <li className="bg-zinc-900 border border-zinc-800 rounded-2xl p-4">
      <Link href={`/collections/${item.id}`} className="block group">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-sm text-white group-hover:underline truncate">{item.name}</span>
          <SourceBadge source={item.source} />
          {item.category && (
            <span className="text-[10px] text-zinc-400 bg-zinc-800 rounded-full px-2 py-0.5">
              {item.category}
            </span>
          )}
        </div>
        <div className="flex items-center gap-2 mt-1 flex-wrap">
          <span className="text-[11px] text-zinc-600">
            Updated {new Date(item.updated_at).toLocaleDateString()}
          </span>
          <span className="text-zinc-700">·</span>
          <span className="text-[11px] text-zinc-600">{item.indicator_count} indicators</span>
          <span className="text-zinc-700">·</span>
          <span className="text-[11px] text-zinc-600">
            {item.linked_workspace_ids.length} investigations
          </span>
          <span className="text-zinc-700">·</span>
          <span className="text-[11px] text-zinc-600">{item.linked_case_ids.length} cases</span>
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

export function SourceBadge({ source }: { source: CollectionSource }) {
  const labels: Record<CollectionSource, string> = {
    manual: "Manual",
    workspace: "From Workspace",
    case: "From Case",
  };
  const classes: Record<CollectionSource, string> = {
    manual: "text-zinc-400 bg-zinc-700/20 border-zinc-600/40",
    workspace: "text-blue-400 bg-blue-500/10 border-blue-500/30",
    case: "text-emerald-400 bg-emerald-500/10 border-emerald-500/30",
  };
  return (
    <span className={`text-[10px] px-2 py-0.5 rounded-full border ${classes[source]}`}>
      {labels[source]}
    </span>
  );
}
