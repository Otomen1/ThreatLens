"use client";

// Same ARIA-tabs + roving-tabindex interaction pattern as
// investigation/shared/DetectionDisclosure.tsx's DetailTabs, adapted for a
// full-page layout (that component caps its panel at max-h-32rem with
// internal scroll, which fits a nested rule-detail card, not a full page).

import { useRef, type KeyboardEvent, type ReactNode } from "react";

export interface DashboardTab {
  key: string;
  label: string;
  content: ReactNode;
}

interface Props {
  idPrefix: string;
  tabs: DashboardTab[];
  activeKey: string;
  onChange: (key: string) => void;
}

export function DashboardTabs({ idPrefix, tabs, activeKey, onChange }: Props) {
  const activeIndex = Math.max(0, tabs.findIndex((t) => t.key === activeKey));
  const tabRefs = useRef<Record<string, HTMLButtonElement | null>>({});

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
    <div>
      <div
        role="tablist"
        aria-label="Operational Dashboard sections"
        onKeyDown={onKeyDown}
        className="flex flex-wrap gap-1 border-b border-zinc-800"
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
              className={`px-4 py-2.5 text-sm font-medium rounded-t-lg border-b-2 transition-colors ${
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
          className="pt-4"
        >
          {tab.key === activeKey ? tab.content : null}
        </div>
      ))}
    </div>
  );
}
