"use client";
import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import { DEFAULT_FEED_DISPLAY, FEED_COLUMNS, exactDate, readFeedDisplay, readFeedReading, relativeAge, writeFeedDisplay,
  type FeedDisplay, type FeedTable } from "@/lib/feedDisplay";

const DisplayContext = createContext({ display: DEFAULT_FEED_DISPLAY, reading: new Set<string>(), now: 0,
  change: (_display: FeedDisplay) => { /* Outside a feed view. */ } });
export const useFeedDisplay = () => useContext(DisplayContext);
export function FeedExperience({ children }: { children: ReactNode }) {
  const [display, setDisplay] = useState(DEFAULT_FEED_DISPLAY);
  const [reading, setReading] = useState(new Set<string>());
  const [now, setNow] = useState(0);
  const [storageWarning, setStorageWarning] = useState(false);
  useEffect(() => {
    const load = () => { setDisplay(readFeedDisplay()); setReading(readFeedReading()); };
    const read = () => setReading(readFeedReading());
    const tick = () => { if (!document.hidden) setNow(Date.now()); };
    load(); tick();
    const timer = window.setInterval(tick, 60_000);
    window.addEventListener("storage", load); window.addEventListener("threatlens:feed-reading", read);
    window.addEventListener("threatlens:preferences", load); document.addEventListener("visibilitychange", tick);
    return () => { clearInterval(timer); window.removeEventListener("storage", load); window.removeEventListener("threatlens:feed-reading", read); window.removeEventListener("threatlens:preferences", load); document.removeEventListener("visibilitychange", tick); };
  }, []);
  const change = (value: FeedDisplay) => { setDisplay(value); setStorageWarning(!writeFeedDisplay(value)); };
  return <DisplayContext.Provider value={{ display, reading, now, change }}>{children}{storageWarning && <p role="status" className="px-4 py-2 text-xs text-amber-200">Display settings apply for this visit; browser storage is unavailable.</p>}</DisplayContext.Provider>;
}
export function FeedTableControls({ table }: { table: FeedTable }) {
  const { display, change } = useFeedDisplay();
  return <details className="rounded-lg border border-zinc-800 px-3 py-2 text-xs text-zinc-400">
    <summary className="cursor-pointer">Table display options</summary>
    <div className="mt-3 flex flex-wrap items-center gap-4"><label>Spacing <select aria-label="Table spacing" className="ml-2 rounded border border-zinc-700 bg-zinc-950 p-1" value={display.density} onChange={(e) => change({ ...display, density: e.target.value === "comfortable" ? "comfortable" : "compact" })}><option value="compact">Compact</option><option value="comfortable">Comfortable</option></select></label>
      <fieldset className="flex flex-wrap gap-3"><legend className="mb-2">Visible columns (title is always shown)</legend>{Object.entries(FEED_COLUMNS[table]).map(([key, label]) => <label key={key}><input type="checkbox" checked={!display.hidden[table]?.includes(key)} onChange={(e) => change({ ...display, hidden: { ...display.hidden, [table]: e.target.checked ? (display.hidden[table] ?? []).filter((v) => v !== key) : [...(display.hidden[table] ?? []), key] } })} /> {label}</label>)}</fieldset>
      <button className="rounded border border-zinc-700 px-2 py-1 text-sky-300" onClick={() => change({ ...display, density: "compact", hidden: { ...display.hidden, [table]: [] } })}>Reset table display</button>
    </div>
  </details>;
}
export function FeedDate({ value, relative = false }: { value: string | null; relative?: boolean }) {
  const { now } = useFeedDisplay();
  if (!value || !Number.isFinite(Date.parse(value))) return <span>Not supplied</span>;
  const exact = now ? exactDate(value) : value;
  return <span className="feed-date relative inline-block"><time tabIndex={0} dateTime={value} title={exact} aria-label={exact}>{now ? relative ? relativeAge(value, now) : new Date(value).toLocaleDateString() : value.slice(0, 10)}</time><span className="feed-date-tip pointer-events-none absolute bottom-full right-0 z-10 mb-1 hidden w-max max-w-64 rounded border border-zinc-700 bg-zinc-950 p-2 text-xs text-zinc-200" aria-hidden="true">{exact}</span></span>;
}
export function ReadDot({ kind, id }: { kind: "news" | "vulnerability" | "ioc"; id: string }) {
  const { reading } = useFeedDisplay();
  return reading.has(`${kind}:${id}`) ? <span className="mr-1 text-[10px] text-zinc-500" aria-label="Read">✓</span> : <span className="mr-1 inline-block h-1.5 w-1.5 rounded-full bg-sky-400" aria-label="Unread" />;
}
