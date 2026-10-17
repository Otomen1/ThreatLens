"use client";

import { useEffect, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import type { FeedRegion } from "@/lib/api/threatFeed";
import { captureFeedPreset, feedPresetHref, readFeedPresets, removeFeedPreset, saveFeedPreset, type FeedPreset, type PresetView } from "@/lib/feedPresets";
import { useToast } from "@/components/ui/ToastProvider";

const control = "rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-xs focus-visible:outline focus-visible:outline-sky-400 disabled:opacity-40";
export function FeedPresets({ view, region }: { view: PresetView; region?: FeedRegion }) {
  const router = useRouter(), params = useSearchParams();
  const { notify } = useToast();
  const [items, setItems] = useState<FeedPreset[]>([]);
  const [selected, setSelected] = useState("");
  const [editing, setEditing] = useState(false);
  const [name, setName] = useState("");
  const [message, setMessage] = useState("");
  useEffect(() => {
    const load = () => setItems(readFeedPresets());
    load(); window.addEventListener("feed-presets", load); window.addEventListener("storage", load);
    return () => { window.removeEventListener("feed-presets", load); window.removeEventListener("storage", load); };
  }, []);
  const active = items.find((item) => item.id === selected);
  function save() {
    try {
      const item = saveFeedPreset(name, captureFeedPreset(view, new URLSearchParams(params.toString()), region));
      setSelected(item.id); setEditing(false); setName(""); setMessage("Preset saved in this browser. Search text was not saved.");
      notify("Filter preset saved locally.");
    } catch (error) { setMessage(error instanceof Error ? error.message : "Couldn't save this preset."); }
  }
  return <details className="mt-4 rounded-lg border border-zinc-800 px-3 py-2 text-xs text-zinc-400">
    <summary className="cursor-pointer focus-visible:outline focus-visible:outline-sky-400">Filter presets · Browser-local</summary>
    <div className="mt-3 flex flex-wrap items-center gap-2">
      <select aria-label="Saved filter presets" value={active?.id ?? ""} onChange={(event) => setSelected(event.target.value)} className={`${control} min-w-0 max-w-full`}><option value="">Choose a preset ({items.length}/10)</option>{items.map((item) => <option key={item.id} value={item.id}>{item.name} · {item.view === "iocs" ? "IOC Reports" : item.view === "news" ? "News" : "Vulnerabilities"}</option>)}</select>
      <button type="button" className={control} disabled={!active} onClick={() => { if (active) { router.push(feedPresetHref(active)); setMessage(""); } }}>Apply preset</button>
      <button type="button" className={control} onClick={() => { setEditing(true); setMessage(""); }}>Save current filters</button>
      <button type="button" className={control} disabled={!active} onClick={() => { if (active) { try { removeFeedPreset(active.id); setSelected(""); setMessage("Preset removed. Bookmarks and other local data are unchanged."); } catch (error) { setMessage(error instanceof Error ? error.message : "Couldn't remove this preset."); } } }}>Remove preset</button>
    </div>
    {editing && <form className="mt-3 flex flex-wrap gap-2" onSubmit={(event) => { event.preventDefault(); save(); }}><input autoFocus aria-label="Preset name" className={`${control} min-w-0 flex-1`} maxLength={60} value={name} onChange={(event) => setName(event.target.value)} placeholder="e.g. Malaysia · 7 days" /><button className={control} disabled={!name.trim()}>Save preset</button><button type="button" className={control} onClick={() => setEditing(false)}>Cancel preset</button></form>}
    <p className="mt-3 text-zinc-500">Up to 10 presets in this browser. Only selected feed filters are saved—not search text, articles, IOC values or PoC results. Applying a preset resets pagination and clears search text.</p>
    <p role="status" className="mt-2 min-h-4 text-amber-200">{message}</p>
  </details>;
}
