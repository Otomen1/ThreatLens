"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useCallback, useEffect, useRef, useState } from "react";

import {
  addIndicator,
  getCase,
  getCollection,
  getInvestigation,
  linkCaseToCollection,
  linkWorkspaceToCollection,
  removeIndicator,
  updateCollection,
  type Case,
  type Collection,
  type IndicatorType,
  type WorkspaceInvestigation,
} from "@/lib/api";
import { entityLabel } from "@/lib/investigation";
import { SourceBadge } from "../page";

type State =
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "ready"; record: Collection };

const INDICATOR_TYPE_OPTIONS: { value: IndicatorType; label: string }[] = [
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

export default function CollectionDetailPage() {
  const params = useParams<{ id: string }>();
  const [state, setState] = useState<State>({ kind: "loading" });
  const [actionError, setActionError] = useState<string | null>(null);
  const abortRef = useRef<AbortController | null>(null);

  const load = useCallback(async () => {
    abortRef.current?.abort();
    const controller = new AbortController();
    abortRef.current = controller;
    setState({ kind: "loading" });
    try {
      const record = await getCollection(params.id, controller.signal);
      setState({ kind: "ready", record });
    } catch (err) {
      if (err instanceof DOMException && err.name === "AbortError") return;
      setState({
        kind: "error",
        message: err instanceof Error ? err.message : "Could not reach the service.",
      });
    }
  }, [params.id]);

  useEffect(() => {
    load();
    return () => abortRef.current?.abort();
  }, [load]);

  async function applyUpdate(changes: Parameters<typeof updateCollection>[1]): Promise<void> {
    if (state.kind !== "ready") return;
    setActionError(null);
    try {
      const record = await updateCollection(state.record.id, changes);
      setState({ kind: "ready", record });
    } catch (err) {
      setActionError(err instanceof Error ? err.message : "That change could not be applied.");
    }
  }

  return (
    <main className="min-h-screen px-4 py-10 sm:py-14">
      <div className="w-full max-w-3xl mx-auto space-y-4">
        <Link
          href="/collections"
          className="text-xs text-zinc-500 hover:text-zinc-300 transition-colors"
        >
          ← Back to Collections
        </Link>

        {state.kind === "loading" && (
          <div className="bg-zinc-900 border border-zinc-800 rounded-2xl p-8 text-center text-sm text-zinc-500">
            Loading collection…
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

        {state.kind === "ready" && (
          <>
            {actionError && (
              <div
                role="alert"
                className="bg-red-500/10 border border-red-500/30 text-red-300 text-sm rounded-xl px-4 py-3"
              >
                {actionError}
              </div>
            )}
            <DetailHeader record={state.record} onUpdate={applyUpdate} />
            <IndicatorsSection record={state.record} onChange={load} onError={setActionError} />
            <LinkedWorkspaces record={state.record} onChange={load} onError={setActionError} />
            <LinkedCases record={state.record} onChange={load} onError={setActionError} />
          </>
        )}
      </div>
    </main>
  );
}

function DetailHeader({
  record,
  onUpdate,
}: {
  record: Collection;
  onUpdate: (changes: Parameters<typeof updateCollection>[1]) => Promise<void>;
}) {
  const [editing, setEditing] = useState(false);
  const [name, setName] = useState(record.name);
  const [description, setDescription] = useState(record.description ?? "");
  const [category, setCategory] = useState(record.category ?? "");
  const [tagsText, setTagsText] = useState(record.tags.join(", "));

  function startEditing() {
    setName(record.name);
    setDescription(record.description ?? "");
    setCategory(record.category ?? "");
    setTagsText(record.tags.join(", "));
    setEditing(true);
  }

  async function saveEdits() {
    await onUpdate({
      name: name.trim() || record.name,
      description: description.trim() || null,
      category: category.trim() || null,
      tags: tagsText
        .split(",")
        .map((t) => t.trim())
        .filter(Boolean),
    });
    setEditing(false);
  }

  return (
    <div className="bg-zinc-900 border border-zinc-800 rounded-2xl p-5 space-y-3">
      <div className="flex items-start justify-between gap-4">
        <div className="min-w-0 flex-1">
          {editing ? (
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              aria-label="Collection name"
              className="w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 text-lg font-semibold text-white focus:outline-none focus:border-zinc-600"
            />
          ) : (
            <h1 className="text-xl font-semibold text-white break-words">{record.name}</h1>
          )}
        </div>
        <div className="shrink-0">
          <SourceBadge source={record.source} />
        </div>
      </div>

      {editing ? (
        <div className="space-y-2">
          <textarea
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="Description"
            aria-label="Collection description"
            rows={3}
            className="w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 text-sm text-white placeholder-zinc-600 focus:outline-none focus:border-zinc-600"
          />
          <div className="flex flex-wrap gap-2">
            <input
              type="text"
              value={category}
              onChange={(e) => setCategory(e.target.value)}
              placeholder="Category"
              aria-label="Collection category"
              className="flex-1 min-w-[140px] bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 text-sm text-white placeholder-zinc-600 focus:outline-none focus:border-zinc-600"
            />
            <input
              type="text"
              value={tagsText}
              onChange={(e) => setTagsText(e.target.value)}
              placeholder="Tags, comma-separated"
              aria-label="Collection tags"
              className="flex-1 min-w-[140px] bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 text-sm text-white placeholder-zinc-600 focus:outline-none focus:border-zinc-600"
            />
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={saveEdits}
              className="text-xs font-medium text-white bg-zinc-700 hover:bg-zinc-600 rounded-lg px-3 py-1.5 transition-colors"
            >
              Save
            </button>
            <button
              onClick={() => setEditing(false)}
              className="text-xs text-zinc-500 hover:text-zinc-300 transition-colors"
            >
              Cancel
            </button>
          </div>
        </div>
      ) : (
        <>
          {record.description && <p className="text-sm text-zinc-400">{record.description}</p>}
          <div className="flex flex-wrap items-center gap-2 pt-2 border-t border-zinc-800">
            {record.category && (
              <span className="text-[11px] text-zinc-500">Category: {record.category}</span>
            )}
            {record.tags.map((tag) => (
              <span
                key={tag}
                className="text-[10px] text-zinc-400 bg-zinc-800 rounded-full px-2 py-0.5"
              >
                {tag}
              </span>
            ))}
            <button
              onClick={startEditing}
              className="text-[10px] font-medium text-zinc-400 hover:text-zinc-200 bg-zinc-800/80 hover:bg-zinc-700 border border-zinc-700 rounded px-2 py-1 transition-colors"
            >
              Edit
            </button>
            <span className="text-[11px] text-zinc-600 ml-auto">
              Created {new Date(record.created_at).toLocaleString()}
            </span>
          </div>
        </>
      )}
    </div>
  );
}

function IndicatorsSection({
  record,
  onChange,
  onError,
}: {
  record: Collection;
  onChange: () => void;
  onError: (message: string) => void;
}) {
  const [type, setType] = useState<IndicatorType>("domain");
  const [value, setValue] = useState("");
  const [tagsText, setTagsText] = useState("");
  const [confidenceText, setConfidenceText] = useState("");
  const [adding, setAdding] = useState(false);

  async function submitAdd() {
    const trimmed = value.trim();
    if (!trimmed) return;
    setAdding(true);
    try {
      const confidence = confidenceText.trim() ? Number(confidenceText.trim()) : undefined;
      await addIndicator(record.id, {
        type,
        value: trimmed,
        tags: tagsText
          .split(",")
          .map((t) => t.trim())
          .filter(Boolean),
        confidence,
      });
      setValue("");
      setTagsText("");
      setConfidenceText("");
      onChange();
    } catch (err) {
      onError(err instanceof Error ? err.message : "Could not add that indicator.");
    } finally {
      setAdding(false);
    }
  }

  async function remove(indicatorType: IndicatorType, indicatorValue: string) {
    try {
      await removeIndicator(record.id, { type: indicatorType, value: indicatorValue });
      onChange();
    } catch (err) {
      onError(err instanceof Error ? err.message : "Could not remove that indicator.");
    }
  }

  return (
    <section
      className="bg-zinc-900 border border-zinc-800 rounded-2xl p-5 space-y-3"
      aria-label="Indicators"
    >
      <h2 className="text-sm font-semibold text-white">
        Indicators
        <span className="ml-2 text-xs font-normal text-zinc-500">
          ({record.indicators.length})
        </span>
      </h2>

      {record.indicators.length === 0 ? (
        <p className="text-sm text-zinc-500">No indicators in this collection yet.</p>
      ) : (
        <ul className="space-y-1.5">
          {record.indicators.map((indicator) => (
            <li
              key={`${indicator.type}:${indicator.value}`}
              className="flex items-start gap-2 rounded-lg border border-zinc-800 bg-zinc-950/50 px-3 py-2"
            >
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-[10px] uppercase tracking-wide text-zinc-500 bg-zinc-800 rounded-full px-2 py-0.5">
                    {indicator.type}
                  </span>
                  <span className="text-sm text-zinc-200 font-mono break-all">
                    {indicator.value}
                  </span>
                  {indicator.confidence !== null && (
                    <span className="text-[11px] text-zinc-500">
                      confidence {indicator.confidence}
                    </span>
                  )}
                </div>
                {indicator.tags.length > 0 && (
                  <div className="flex items-center gap-1 mt-1 flex-wrap">
                    {indicator.tags.map((tag) => (
                      <span
                        key={tag}
                        className="text-[10px] text-zinc-400 bg-zinc-800 rounded-full px-2 py-0.5"
                      >
                        {tag}
                      </span>
                    ))}
                  </div>
                )}
              </div>
              <button
                onClick={() => remove(indicator.type, indicator.value)}
                aria-label={`Remove ${indicator.type} ${indicator.value}`}
                className="shrink-0 text-[11px] text-zinc-500 hover:text-red-400 transition-colors px-2 py-1"
              >
                Remove
              </button>
            </li>
          ))}
        </ul>
      )}

      <div className="space-y-2 pt-2 border-t border-zinc-800">
        <div className="flex flex-wrap gap-2">
          <select
            value={type}
            onChange={(e) => setType(e.target.value as IndicatorType)}
            aria-label="Indicator type"
            className="bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 text-sm text-zinc-300 focus:outline-none"
          >
            {INDICATOR_TYPE_OPTIONS.map((opt) => (
              <option key={opt.value} value={opt.value}>
                {opt.label}
              </option>
            ))}
          </select>
          <input
            type="text"
            value={value}
            onChange={(e) => setValue(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && submitAdd()}
            placeholder="Value"
            aria-label="Indicator value"
            className="flex-1 min-w-[160px] bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 text-sm text-white placeholder-zinc-600 focus:outline-none focus:border-zinc-600"
          />
        </div>
        <div className="flex flex-wrap gap-2">
          <input
            type="text"
            value={tagsText}
            onChange={(e) => setTagsText(e.target.value)}
            placeholder="Tags, comma-separated (optional)"
            aria-label="Indicator tags"
            className="flex-1 min-w-[160px] bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 text-sm text-white placeholder-zinc-600 focus:outline-none focus:border-zinc-600"
          />
          <input
            type="number"
            min={0}
            max={100}
            value={confidenceText}
            onChange={(e) => setConfidenceText(e.target.value)}
            placeholder="Confidence 0-100 (optional)"
            aria-label="Indicator confidence"
            className="w-48 bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 text-sm text-white placeholder-zinc-600 focus:outline-none focus:border-zinc-600"
          />
        </div>
        <button
          onClick={submitAdd}
          disabled={adding || !value.trim()}
          className="text-xs font-medium text-white bg-zinc-700 hover:bg-zinc-600 disabled:opacity-40 disabled:cursor-not-allowed rounded-lg px-3 py-1.5 transition-colors"
        >
          {adding ? "Adding…" : "Add Indicator"}
        </button>
      </div>
    </section>
  );
}

function LinkedWorkspaces({
  record,
  onChange,
  onError,
}: {
  record: Collection;
  onChange: () => void;
  onError: (message: string) => void;
}) {
  const [newId, setNewId] = useState("");
  const [linking, setLinking] = useState(false);

  async function submitLink() {
    const id = newId.trim();
    if (!id) return;
    setLinking(true);
    try {
      await linkWorkspaceToCollection(record.id, id);
      setNewId("");
      onChange();
    } catch (err) {
      onError(
        err instanceof Error
          ? err.message
          : "Could not link that investigation. Check the id and try again.",
      );
    } finally {
      setLinking(false);
    }
  }

  return (
    <section
      className="bg-zinc-900 border border-zinc-800 rounded-2xl p-5 space-y-3"
      aria-label="Linked investigations"
    >
      <h2 className="text-sm font-semibold text-white">
        Linked Investigations
        <span className="ml-2 text-xs font-normal text-zinc-500">
          ({record.linked_workspace_ids.length})
        </span>
      </h2>

      {record.linked_workspace_ids.length === 0 ? (
        <p className="text-sm text-zinc-500">No investigations linked to this collection yet.</p>
      ) : (
        <ul className="space-y-1.5">
          {record.linked_workspace_ids.map((id) => (
            <LinkedInvestigationRow key={id} workspaceId={id} />
          ))}
        </ul>
      )}

      <div className="flex items-center gap-2 pt-2 border-t border-zinc-800">
        <input
          type="text"
          value={newId}
          onChange={(e) => setNewId(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && submitLink()}
          placeholder="Workspace investigation id"
          aria-label="Workspace investigation id to link"
          className="flex-1 min-w-[160px] bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 text-xs text-white placeholder-zinc-600 focus:outline-none focus:border-zinc-600"
        />
        <button
          onClick={submitLink}
          disabled={linking || !newId.trim()}
          className="text-xs font-medium text-white bg-zinc-700 hover:bg-zinc-600 disabled:opacity-40 disabled:cursor-not-allowed rounded-lg px-3 py-1.5 transition-colors"
        >
          {linking ? "Linking…" : "Link"}
        </button>
      </div>
    </section>
  );
}

function LinkedInvestigationRow({ workspaceId }: { workspaceId: string }) {
  const [investigation, setInvestigation] = useState<WorkspaceInvestigation | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    let cancelled = false;
    getInvestigation(workspaceId)
      .then((record) => {
        if (!cancelled) setInvestigation(record);
      })
      .catch(() => {
        if (!cancelled) setFailed(true);
      });
    return () => {
      cancelled = true;
    };
  }, [workspaceId]);

  return (
    <li className="rounded-lg border border-zinc-800 bg-zinc-950/50 px-3 py-2">
      <Link href={`/workspace/${workspaceId}`} className="block group">
        {investigation ? (
          <span className="flex items-center gap-2 flex-wrap">
            <span className="text-sm text-zinc-200 group-hover:underline truncate">
              {investigation.title}
            </span>
            <span className="text-[10px] text-zinc-500">
              {entityLabel(investigation.investigation_type)}
            </span>
          </span>
        ) : failed ? (
          <span className="text-xs text-zinc-500 font-mono">{workspaceId} (unavailable)</span>
        ) : (
          <span className="text-xs text-zinc-500 animate-pulse">Loading…</span>
        )}
      </Link>
    </li>
  );
}

function LinkedCases({
  record,
  onChange,
  onError,
}: {
  record: Collection;
  onChange: () => void;
  onError: (message: string) => void;
}) {
  const [newId, setNewId] = useState("");
  const [linking, setLinking] = useState(false);

  async function submitLink() {
    const id = newId.trim();
    if (!id) return;
    setLinking(true);
    try {
      await linkCaseToCollection(record.id, id);
      setNewId("");
      onChange();
    } catch (err) {
      onError(
        err instanceof Error
          ? err.message
          : "Could not link that case. Check the id and try again.",
      );
    } finally {
      setLinking(false);
    }
  }

  return (
    <section
      className="bg-zinc-900 border border-zinc-800 rounded-2xl p-5 space-y-3"
      aria-label="Linked cases"
    >
      <h2 className="text-sm font-semibold text-white">
        Linked Cases
        <span className="ml-2 text-xs font-normal text-zinc-500">
          ({record.linked_case_ids.length})
        </span>
      </h2>

      {record.linked_case_ids.length === 0 ? (
        <p className="text-sm text-zinc-500">No cases linked to this collection yet.</p>
      ) : (
        <ul className="space-y-1.5">
          {record.linked_case_ids.map((id) => (
            <LinkedCaseRow key={id} caseId={id} />
          ))}
        </ul>
      )}

      <div className="flex items-center gap-2 pt-2 border-t border-zinc-800">
        <input
          type="text"
          value={newId}
          onChange={(e) => setNewId(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && submitLink()}
          placeholder="Case id"
          aria-label="Case id to link"
          className="flex-1 min-w-[160px] bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 text-xs text-white placeholder-zinc-600 focus:outline-none focus:border-zinc-600"
        />
        <button
          onClick={submitLink}
          disabled={linking || !newId.trim()}
          className="text-xs font-medium text-white bg-zinc-700 hover:bg-zinc-600 disabled:opacity-40 disabled:cursor-not-allowed rounded-lg px-3 py-1.5 transition-colors"
        >
          {linking ? "Linking…" : "Link"}
        </button>
      </div>
    </section>
  );
}

function LinkedCaseRow({ caseId }: { caseId: string }) {
  const [record, setRecord] = useState<Case | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    let cancelled = false;
    getCase(caseId)
      .then((c) => {
        if (!cancelled) setRecord(c);
      })
      .catch(() => {
        if (!cancelled) setFailed(true);
      });
    return () => {
      cancelled = true;
    };
  }, [caseId]);

  return (
    <li className="rounded-lg border border-zinc-800 bg-zinc-950/50 px-3 py-2">
      <Link href={`/cases/${caseId}`} className="block group">
        {record ? (
          <span className="text-sm text-zinc-200 group-hover:underline truncate">
            {record.title}
          </span>
        ) : failed ? (
          <span className="text-xs text-zinc-500 font-mono">{caseId} (unavailable)</span>
        ) : (
          <span className="text-xs text-zinc-500 animate-pulse">Loading…</span>
        )}
      </Link>
    </li>
  );
}
