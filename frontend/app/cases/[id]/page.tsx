"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useCallback, useEffect, useRef, useState } from "react";

import {
  addCaseNote,
  getCase,
  getInvestigation,
  linkWorkspaceToCase,
  unlinkWorkspaceFromCase,
  updateCase,
  type Case,
  type CasePriority,
  type CaseStatus,
  type WorkspaceInvestigation,
} from "@/lib/api";
import { entityLabel } from "@/lib/investigation";

type State =
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "ready"; record: Case };

const STATUS_OPTIONS: CaseStatus[] = ["open", "in_progress", "resolved", "closed"];
const PRIORITY_OPTIONS: CasePriority[] = ["low", "medium", "high", "critical"];

export default function CaseDetailPage() {
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
      const record = await getCase(params.id, controller.signal);
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

  async function applyUpdate(
    changes: Parameters<typeof updateCase>[1],
  ): Promise<void> {
    if (state.kind !== "ready") return;
    setActionError(null);
    try {
      const record = await updateCase(state.record.id, changes);
      setState({ kind: "ready", record });
    } catch (err) {
      setActionError(err instanceof Error ? err.message : "That change could not be applied.");
    }
  }

  return (
    <main className="min-h-screen px-4 py-10 sm:py-14">
      <div className="w-full max-w-3xl mx-auto space-y-4">
        <Link href="/cases" className="text-xs text-zinc-500 hover:text-zinc-300 transition-colors">
          ← Back to Cases
        </Link>

        {state.kind === "loading" && (
          <div className="bg-zinc-900 border border-zinc-800 rounded-2xl p-8 text-center text-sm text-zinc-500">
            Loading case…
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
            <LinkedInvestigations record={state.record} onChange={load} onError={setActionError} />
            <NotesSection record={state.record} onChange={load} onError={setActionError} />
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
  record: Case;
  onUpdate: (changes: Parameters<typeof updateCase>[1]) => Promise<void>;
}) {
  const [editing, setEditing] = useState(false);
  const [title, setTitle] = useState(record.title);
  const [description, setDescription] = useState(record.description ?? "");
  const [owner, setOwner] = useState(record.owner ?? "");
  const [tagsText, setTagsText] = useState(record.tags.join(", "));

  function startEditing() {
    setTitle(record.title);
    setDescription(record.description ?? "");
    setOwner(record.owner ?? "");
    setTagsText(record.tags.join(", "));
    setEditing(true);
  }

  async function saveEdits() {
    await onUpdate({
      title: title.trim() || record.title,
      description: description.trim() || null,
      owner: owner.trim() || null,
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
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              aria-label="Case title"
              className="w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 text-lg font-semibold text-white focus:outline-none focus:border-zinc-600"
            />
          ) : (
            <h1 className="text-xl font-semibold text-white break-words">{record.title}</h1>
          )}
        </div>
        <div className="shrink-0 flex items-center gap-2">
          <select
            value={record.status}
            onChange={(e) => onUpdate({ status: e.target.value as CaseStatus })}
            aria-label="Case status"
            className="bg-zinc-800 border border-zinc-700 rounded-lg px-2.5 py-1.5 text-xs text-zinc-300 focus:outline-none"
          >
            {STATUS_OPTIONS.map((s) => (
              <option key={s} value={s}>
                {s.replace("_", " ")}
              </option>
            ))}
          </select>
          <select
            value={record.priority}
            onChange={(e) => onUpdate({ priority: e.target.value as CasePriority })}
            aria-label="Case priority"
            className="bg-zinc-800 border border-zinc-700 rounded-lg px-2.5 py-1.5 text-xs text-zinc-300 focus:outline-none"
          >
            {PRIORITY_OPTIONS.map((p) => (
              <option key={p} value={p}>
                {p}
              </option>
            ))}
          </select>
        </div>
      </div>

      {editing ? (
        <div className="space-y-2">
          <textarea
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="Description"
            aria-label="Case description"
            rows={3}
            className="w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 text-sm text-white placeholder-zinc-600 focus:outline-none focus:border-zinc-600"
          />
          <div className="flex flex-wrap gap-2">
            <input
              type="text"
              value={owner}
              onChange={(e) => setOwner(e.target.value)}
              placeholder="Owner"
              aria-label="Case owner"
              className="flex-1 min-w-[140px] bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 text-sm text-white placeholder-zinc-600 focus:outline-none focus:border-zinc-600"
            />
            <input
              type="text"
              value={tagsText}
              onChange={(e) => setTagsText(e.target.value)}
              placeholder="Tags, comma-separated"
              aria-label="Case tags"
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
            {record.owner && (
              <span className="text-[11px] text-zinc-500">Owner: {record.owner}</span>
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

function LinkedInvestigations({
  record,
  onChange,
  onError,
}: {
  record: Case;
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
      await linkWorkspaceToCase(record.id, id);
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

  async function unlink(workspaceId: string) {
    try {
      await unlinkWorkspaceFromCase(record.id, workspaceId);
      onChange();
    } catch (err) {
      onError(err instanceof Error ? err.message : "Could not unlink that investigation.");
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
        <p className="text-sm text-zinc-500">No investigations linked to this case yet.</p>
      ) : (
        <ul className="space-y-1.5">
          {record.linked_workspace_ids.map((id) => (
            <LinkedInvestigationRow key={id} workspaceId={id} onUnlink={() => unlink(id)} />
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

function LinkedInvestigationRow({
  workspaceId,
  onUnlink,
}: {
  workspaceId: string;
  onUnlink: () => void;
}) {
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
    <li className="flex items-center gap-2 rounded-lg border border-zinc-800 bg-zinc-950/50 px-3 py-2">
      <Link href={`/workspace/${workspaceId}`} className="flex-1 min-w-0 group">
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
      <button
        onClick={onUnlink}
        aria-label={`Unlink ${workspaceId}`}
        className="shrink-0 text-[11px] text-zinc-500 hover:text-red-400 transition-colors px-2 py-1"
      >
        Unlink
      </button>
    </li>
  );
}

function NotesSection({
  record,
  onChange,
  onError,
}: {
  record: Case;
  onChange: () => void;
  onError: (message: string) => void;
}) {
  const [author, setAuthor] = useState("");
  const [content, setContent] = useState("");
  const [adding, setAdding] = useState(false);

  async function submit() {
    if (!author.trim() || !content.trim()) return;
    setAdding(true);
    try {
      await addCaseNote(record.id, author.trim(), content.trim());
      setContent("");
      onChange();
    } catch (err) {
      onError(err instanceof Error ? err.message : "Could not add that note.");
    } finally {
      setAdding(false);
    }
  }

  return (
    <section className="bg-zinc-900 border border-zinc-800 rounded-2xl p-5 space-y-3" aria-label="Notes">
      <h2 className="text-sm font-semibold text-white">
        Notes
        <span className="ml-2 text-xs font-normal text-zinc-500">({record.notes.length})</span>
      </h2>

      {record.notes.length === 0 ? (
        <p className="text-sm text-zinc-500">No notes yet.</p>
      ) : (
        <ul className="space-y-2">
          {record.notes.map((note, i) => (
            <li key={i} className="rounded-lg border border-zinc-800 bg-zinc-950/50 p-3">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-xs font-medium text-zinc-300">{note.author}</span>
                <span className="text-[11px] text-zinc-600 font-mono">
                  {new Date(note.timestamp).toLocaleString()}
                </span>
              </div>
              <p className="text-sm text-zinc-400 mt-1 whitespace-pre-wrap break-words">
                {note.content}
              </p>
            </li>
          ))}
        </ul>
      )}

      <div className="space-y-2 pt-2 border-t border-zinc-800">
        <input
          type="text"
          value={author}
          onChange={(e) => setAuthor(e.target.value)}
          placeholder="Your name"
          aria-label="Note author"
          className="w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 text-sm text-white placeholder-zinc-600 focus:outline-none focus:border-zinc-600"
        />
        <textarea
          value={content}
          onChange={(e) => setContent(e.target.value)}
          placeholder="Add a note…"
          aria-label="Note content"
          rows={2}
          className="w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 text-sm text-white placeholder-zinc-600 focus:outline-none focus:border-zinc-600"
        />
        <button
          onClick={submit}
          disabled={adding || !author.trim() || !content.trim()}
          className="text-xs font-medium text-white bg-zinc-700 hover:bg-zinc-600 disabled:opacity-40 disabled:cursor-not-allowed rounded-lg px-3 py-1.5 transition-colors"
        >
          {adding ? "Adding…" : "Add Note"}
        </button>
      </div>
    </section>
  );
}
