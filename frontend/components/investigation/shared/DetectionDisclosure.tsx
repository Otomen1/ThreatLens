"use client";

// Shared presentation primitives for the Detection Engineering and Detection
// Knowledge panels. Both follow the same drill-down: Language → Rule → Rule
// Details, so the accordion/tab shell lives here once instead of twice.

import { useRef, type KeyboardEvent, type ReactNode } from "react";

export function Badge({ className, children }: { className?: string; children: ReactNode }) {
  return (
    <span className={`text-[10px] font-mono rounded border px-1.5 py-0.5 ${className ?? ""}`}>
      {children}
    </span>
  );
}

export function IconButton({ label, onClick }: { label: string; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className="text-[10px] font-medium text-zinc-400 hover:text-zinc-200 bg-zinc-800/80 hover:bg-zinc-700 border border-zinc-700 rounded px-2 py-1 transition-colors"
    >
      {label}
    </button>
  );
}

export function Chevron({ expanded }: { expanded: boolean }) {
  return (
    <svg
      width="14"
      height="14"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      className={`shrink-0 text-zinc-500 transition-transform duration-150 ${expanded ? "rotate-180" : ""}`}
      aria-hidden
    >
      <polyline points="6 9 12 15 18 9" />
    </svg>
  );
}

export function InfoIcon() {
  return (
    <svg
      width="18"
      height="18"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      className="mt-0.5 shrink-0 text-zinc-500"
      aria-hidden
    >
      <circle cx="12" cy="12" r="10" />
      <path d="M12 16v-4M12 8h.01" />
    </svg>
  );
}

interface LanguageGroupProps {
  id: string;
  label: string;
  count: number;
  expanded: boolean;
  onToggle: () => void;
  children: ReactNode;
}

/** A collapsed-by-default language section: name, rule count, chevron — nothing else. */
export function LanguageGroupHeader({
  id,
  label,
  count,
  expanded,
  onToggle,
  children,
}: LanguageGroupProps) {
  const panelId = `${id}-panel`;
  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-950/40 overflow-hidden">
      <button
        onClick={onToggle}
        aria-expanded={expanded}
        aria-controls={panelId}
        id={id}
        className="w-full flex items-center gap-3 px-4 py-2.5 text-left hover:bg-zinc-800/50 transition-colors"
      >
        <Chevron expanded={expanded} />
        <span className="flex-1 text-sm font-medium text-zinc-200">{label}</span>
        <span className="text-[11px] font-mono text-zinc-400 bg-zinc-800 rounded-full px-2 py-0.5">
          {count}
        </span>
      </button>
      {expanded && (
        <div
          id={panelId}
          role="region"
          aria-labelledby={id}
          className="border-t border-zinc-800 px-3 py-3 space-y-2"
        >
          {children}
        </div>
      )}
    </div>
  );
}

export interface DetailTab {
  key: string;
  label: string;
  content: ReactNode;
}

interface DetailTabsProps {
  idPrefix: string;
  tabs: DetailTab[];
  activeKey: string;
  onChange: (key: string) => void;
}

/** A tabbed rule-detail panel: Overview is conventionally the first/default tab. */
export function DetailTabs({ idPrefix, tabs, activeKey, onChange }: DetailTabsProps) {
  const activeIndex = Math.max(
    0,
    tabs.findIndex((t) => t.key === activeKey),
  );
  const tabRefs = useRef<Record<string, HTMLButtonElement | null>>({});

  // Roving tabindex: keyboard navigation must move DOM focus along with the
  // selection, not just update aria-selected (WAI-ARIA tabs pattern).
  function onKeyDown(event: KeyboardEvent<HTMLDivElement>) {
    let next = activeIndex;
    if (event.key === "ArrowRight") next = (activeIndex + 1) % tabs.length;
    else if (event.key === "ArrowLeft") next = (activeIndex - 1 + tabs.length) % tabs.length;
    else if (event.key === "Home") next = 0;
    else if (event.key === "End") next = tabs.length - 1;
    else return;
    event.preventDefault();
    const nextKey = tabs[next].key;
    onChange(nextKey);
    tabRefs.current[nextKey]?.focus();
  }

  return (
    <div className="rounded-lg border border-zinc-800 bg-zinc-950/60">
      <div
        role="tablist"
        aria-label="Rule details"
        onKeyDown={onKeyDown}
        className="flex flex-wrap gap-1 border-b border-zinc-800 px-2 pt-2"
      >
        {tabs.map((tab) => {
          const selected = tab.key === activeKey;
          return (
            <button
              key={tab.key}
              ref={(el) => {
                tabRefs.current[tab.key] = el;
              }}
              type="button"
              role="tab"
              id={`${idPrefix}-tab-${tab.key}`}
              aria-selected={selected}
              aria-controls={`${idPrefix}-panel-${tab.key}`}
              tabIndex={selected ? 0 : -1}
              onClick={() => onChange(tab.key)}
              className={`px-2.5 py-1.5 text-[11px] font-medium rounded-t-md border-b-2 transition-colors ${
                selected
                  ? "border-sky-500 text-sky-300"
                  : "border-transparent text-zinc-500 hover:text-zinc-300"
              }`}
            >
              {tab.label}
            </button>
          );
        })}
      </div>
      {tabs.map((tab) => (
        <div
          key={tab.key}
          role="tabpanel"
          id={`${idPrefix}-panel-${tab.key}`}
          aria-labelledby={`${idPrefix}-tab-${tab.key}`}
          hidden={tab.key !== activeKey}
          tabIndex={0}
          className="p-3 max-h-[32rem] overflow-y-auto"
        >
          {tab.key === activeKey ? tab.content : null}
        </div>
      ))}
    </div>
  );
}

export function Field({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="min-w-0">
      <span className="block text-[9px] uppercase tracking-wider text-zinc-600">{label}</span>
      <span className={`block truncate text-zinc-300 ${mono ? "font-mono" : ""}`}>{value}</span>
    </div>
  );
}

/** The full rule body — same monospace rendering as before, just relocated into a tab. */
export function CodeViewer({ content }: { content: string }) {
  return (
    <pre className="overflow-x-auto rounded-lg bg-black/40 p-3 text-[11px] leading-relaxed text-zinc-300">
      <code className="font-mono whitespace-pre">{content}</code>
    </pre>
  );
}
