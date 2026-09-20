"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useMemo, useRef, useState } from "react";

import { ToastProvider } from "@/components/ui/ToastProvider";

const COMMANDS = [
  ["Search", "/"], ["Threat Feed", "/threat-feed"], ["Investigations", "/workspace"],
  ["Detections", "/detections"], ["Cases", "/cases"], ["Dashboard", "/dashboard"],
  ["Exposure", "/exposure"], ["Identity", "/identity"], ["Correlation", "/correlation"],
  ["Settings", "/settings"], ["Start investigation", "/?focus=search"],
  ["Create case", "/cases?focus=create"], ["Generate password", "/identity?tab=password&focus=generator"],
  ["Manage backups", "/settings?focus=backup"],
] as const;

export function AppEnhancements({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const [progress, setProgress] = useState(false);
  const [palette, setPalette] = useState(false);
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState(0);
  const [showTop, setShowTop] = useState(false);
  const previousFocus = useRef<HTMLElement | null>(null);
  const dialogRef = useRef<HTMLDivElement>(null);
  const matches = useMemo(() => COMMANDS.filter(([label]) => label.toLowerCase().includes(query.toLowerCase())).slice(0, 10), [query]);

  useEffect(() => {
    setProgress(false);
    setPalette(false);
    const focus = new URLSearchParams(window.location.search).get("focus");
    if (focus) window.setTimeout(() => document.querySelector<HTMLElement>(`[data-focus="${CSS.escape(focus)}"]`)?.focus(), 50);
  }, [pathname]);

  useEffect(() => {
    const stop = window.setTimeout(() => setProgress(false), progress ? 8000 : 0);
    return () => window.clearTimeout(stop);
  }, [progress]);

  useEffect(() => {
    if (!palette && previousFocus.current) {
      previousFocus.current.focus();
      previousFocus.current = null;
    }
  }, [palette]);

  useEffect(() => {
    function onClick(event: MouseEvent) {
      const anchor = (event.target as Element).closest("a");
      if (!anchor || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey || anchor.target === "_blank" || anchor.hasAttribute("download")) return;
      const url = new URL(anchor.href, window.location.href);
      if (url.origin === window.location.origin && url.pathname !== window.location.pathname && !url.hash) setProgress(true);
    }
    function onKey(event: KeyboardEvent) {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setPalette((open) => {
          if (!open) previousFocus.current = document.activeElement as HTMLElement;
          return !open;
        });
      } else if (event.key === "Escape") setPalette(false);
    }
    function onScroll() { setShowTop(window.scrollY > 600); }
    document.addEventListener("click", onClick, true);
    document.addEventListener("keydown", onKey);
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => {
      document.removeEventListener("click", onClick, true);
      document.removeEventListener("keydown", onKey);
      window.removeEventListener("scroll", onScroll);
    };
  }, []);

  return (
    <ToastProvider>
      {progress && <div role="progressbar" aria-label="Loading page" className="route-progress fixed left-0 right-0 top-14 z-[60] h-0.5 overflow-hidden bg-sky-950"><span className="block h-full w-1/3 bg-sky-400" /></div>}
      <div key={pathname} className="animate-page-enter">{children}</div>
      {showTop && <button type="button" aria-label="Back to top" onClick={() => window.scrollTo({ top: 0, behavior: window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth" })} className="fixed bottom-5 left-5 z-30 rounded-full border border-zinc-700 bg-zinc-900/95 px-3 py-2 text-xs text-zinc-300 shadow-xl hover:bg-zinc-800">↑ Top</button>}
      {palette && <div className="fixed inset-0 z-[80] flex items-start justify-center bg-black/60 px-4 pt-[15vh] backdrop-blur-sm" role="dialog" aria-modal="true" aria-label="Command menu" onMouseDown={(event) => event.target === event.currentTarget && setPalette(false)}>
        <div ref={dialogRef} onKeyDown={(event) => { if (event.key !== "Tab") return; const focusable = [...(dialogRef.current?.querySelectorAll<HTMLElement>('input,a,button') ?? [])]; if (!focusable.length) return; const first = focusable[0]; const last = focusable.at(-1)!; if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); } else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); } }} className="animate-ui-enter w-full max-w-lg overflow-hidden rounded-2xl border border-zinc-700 bg-zinc-950 shadow-2xl">
          <input autoFocus value={query} onChange={(event) => { setQuery(event.target.value); setSelected(0); }} onKeyDown={(event) => { if (event.key === "ArrowDown" && matches.length) { event.preventDefault(); setSelected((value) => Math.min(value + 1, matches.length - 1)); } if (event.key === "ArrowUp") { event.preventDefault(); setSelected((value) => Math.max(0, value - 1)); } if (event.key === "Enter") document.getElementById(`command-${selected}`)?.click(); }} placeholder="Search pages and actions…" aria-label="Search commands" className="w-full border-b border-zinc-800 bg-transparent px-4 py-4 text-sm text-white outline-none placeholder:text-zinc-600" />
          <div className="max-h-80 overflow-y-auto p-2">
            {matches.map(([label, href], index) => <Link id={`command-${index}`} key={`${label}-${href}`} href={href} onClick={() => { setPalette(false); const focus = new URL(href, window.location.href).searchParams.get("focus"); if (focus) window.setTimeout(() => document.querySelector<HTMLElement>(`[data-focus="${CSS.escape(focus)}"]`)?.focus(), 100); }} onMouseEnter={() => setSelected(index)} className={`block rounded-lg px-3 py-2.5 text-sm ${selected === index ? "bg-zinc-800 text-white" : "text-zinc-400 hover:bg-zinc-900 hover:text-white"}`}>{label}<span className="float-right text-xs text-zinc-600">{href}</span></Link>)}
            {!matches.length && <p className="px-3 py-6 text-center text-sm text-zinc-600">No matching command.</p>}
          </div>
          <p className="border-t border-zinc-800 px-4 py-2 text-[10px] text-zinc-600">↑↓ select · Enter open · Esc close</p>
        </div>
      </div>}
    </ToastProvider>
  );
}
