"use client";

import type { ReactNode } from "react";
import type { FeedRegion } from "@/lib/api/threatFeed";
import type { FeedTable } from "@/lib/feedDisplay";
import { FeedFilters } from "./FeedFilters";
import { FeedPresets } from "./FeedPresets";
import { FeedTableControls } from "./FeedExperience";

/** Primary filters stay visible; optional presentation controls share one disclosure. */
export function FeedToolbar({ table, region, children }: { table: FeedTable; region?: FeedRegion; children: ReactNode }) {
  const view = table === "news" ? "news" : table === "vulnerability" ? "vulnerabilities" : "iocs";
  return <section aria-label="Feed toolbar" className="feed-toolbar space-y-3 rounded-xl border border-zinc-800 bg-zinc-900/60 p-3 sm:p-4">
    {children}
    <div className="flex flex-wrap items-start justify-between gap-3">
      <FeedFilters newsRegion={region} />
      <details className="feed-more-options min-w-0 text-xs text-zinc-300">
        <summary className="feed-interactive cursor-pointer rounded-lg border border-zinc-700 px-3 py-2 hover:bg-zinc-800 focus-visible:outline focus-visible:outline-sky-400">More options</summary>
        <div className="mt-3 space-y-3"><FeedPresets view={view} region={region} /><FeedTableControls table={table} /></div>
      </details>
    </div>
  </section>;
}
