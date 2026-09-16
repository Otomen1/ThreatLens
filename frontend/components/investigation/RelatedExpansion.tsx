"use client";

import { useMemo, useState } from "react";
import type { AttributedRelationship, Entity } from "@/lib/api";

export function RelatedExpansion({ entity, relationships, onInvestigate }: { entity: Entity; relationships: AttributedRelationship[]; onInvestigate?: (query: string) => void }) {
  const candidates = useMemo(() => {
    const seen = new Set([entity.normalized_value.toLowerCase()]);
    return relationships.flatMap((item) => {
      const value = item.relationship.target_value.trim(); const key = value.toLowerCase();
      if (!value || seen.has(key)) return [];
      seen.add(key); return [{ value, type: item.relationship.target_type, relation: item.relationship.relationship, sources: item.sources, confidence: item.relationship.confidence }];
    }).slice(0, 10);
  }, [entity.normalized_value, relationships]);
  const [selected, setSelected] = useState(() => new Set(candidates.map((item) => item.value)));
  if (!onInvestigate || candidates.length === 0) return null;
  return <section className="rounded-2xl border border-zinc-800 bg-zinc-900 p-5"><h2 className="text-sm font-semibold text-white">Related IOC expansion</h2><p className="mt-1 text-xs text-zinc-500">Optional one-level pivot. Confirming may consume provider quota.</p><div className="mt-3 space-y-2">{candidates.map((item) => <label key={item.value} className="flex flex-wrap items-center gap-2 rounded-lg border border-zinc-800 p-3 text-xs"><input type="checkbox" checked={selected.has(item.value)} onChange={(event) => setSelected((current) => { const next = new Set(current); if (event.target.checked) next.add(item.value); else next.delete(item.value); return next; })} /><span className="font-mono text-zinc-200">{item.value}</span><span className="text-zinc-500">{item.relation} · {item.type} · {item.sources.join(", ")}{item.confidence !== null ? ` · ${item.confidence}%` : ""}</span></label>)}</div><button disabled={!selected.size} onClick={() => onInvestigate([...selected].join("\n"))} className="mt-3 rounded-lg bg-sky-600 px-3 py-2 text-xs text-white disabled:opacity-40">Preview {selected.size} related IOC{selected.size === 1 ? "" : "s"}</button></section>;
}
