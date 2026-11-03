import type { ReactNode } from "react";

export function FeedStats({ label, items, columns = 3 }: { label: string; items: { label: string; value: ReactNode; compact?: boolean }[]; columns?: 3 | 4 }) {
  return <section aria-label={label} className={`feed-stats grid gap-3 ${columns === 4 ? "grid-cols-2 sm:grid-cols-4" : "sm:grid-cols-3"}`}>
    {items.map((item) => <div key={item.label} className="feed-stat">
      <p className="text-xs leading-5 text-zinc-400">{item.label}</p>
      <p className={`mt-2 tabular-nums text-zinc-100 ${item.compact ? "text-sm font-medium leading-6" : "text-2xl font-semibold"}`}>{item.value}</p>
    </div>)}
  </section>;
}

export function FeedNotice({ children, warning = false }: { children?: ReactNode; warning?: boolean }) {
  return <p role="status" aria-live="polite" className={children ? `feed-notice ${warning ? "feed-notice-warning" : ""}` : "sr-only"}>{children}</p>;
}

export function FeedRefreshHelp() {
  return <details className="text-xs text-zinc-400">
    <summary className="feed-interactive w-fit cursor-pointer rounded py-1 focus-visible:outline">About reload and refresh</summary>
    <p className="mt-2 max-w-2xl leading-5">Reload reads saved data only. Refresh sources contacts publishers and respects the 30-minute public cooldown. Source-reported intelligence remains unverified until investigated.</p>
  </details>;
}
