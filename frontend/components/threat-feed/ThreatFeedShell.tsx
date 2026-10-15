"use client";

import { Suspense, useEffect, useRef } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { FeedPanels } from "./FeedPanels";
import type { FeedTab } from "./FeedPanelContext";
import type { FeedRegion } from "@/lib/api/threatFeed";
import { NEWS_REGIONS, newsHref } from "@/lib/newsFeed";
import { FeedStatus } from "./FeedStatus";
import { UnifiedFeedSearch } from "./FeedWorkflow";
import { FeedHeader } from "./FeedHeader";
import { SavedFeed } from "./SavedFeed";
import { FeedFilters } from "./FeedFilters";
import { LoadingRows } from "@/components/ui/Skeleton";
import { FeedViewNavigation } from "./FeedViewNavigation";
import { FeedExperience } from "./FeedExperience";
import { FeedPreviewProvider } from "./FeedPreview";

function FeedTabs({ region }: { region?: FeedRegion }) {
  const params = useSearchParams();
  const router = useRouter();
  const headerRef = useRef<HTMLElement>(null);
  const selected = region ? "news" : ["vulnerabilities", "poc", "iocs"].includes(params.get("tab") ?? "") ? params.get("tab") : "news";
  const legacyRegion = !region && selected === "news" && !params.has("view") ? NEWS_REGIONS.find((value) => value === params.get("region")) : undefined;
  const canonical = legacyRegion ? newsHref(legacyRegion, params, true) : !region && selected === "news" && !params.has("view") && (params.has("sort") || params.has("page") || params.has("region")) ? newsHref(undefined, params) : null;
  useEffect(() => { if (canonical) router.replace(canonical); }, [canonical, router]);
  if (canonical) return <LoadingRows rows={5} label="Opening News…" />;
  return <FeedExperience><FeedPreviewProvider>
    <FeedHeader headerRef={headerRef} />
    <div className="threat-feed-frame">
      <div className="mx-auto max-w-6xl px-4">
        <FeedViewNavigation selected={selected} headerRef={headerRef} />
        <FeedStatus manualPoc={selected === "poc"} />
        {!params.has("view") && <FeedFilters poc={selected === "poc"} newsRegion={region} />}
      </div>
      {params.get("view") === "saved" ? <SavedFeed /> : params.get("view") === "search" ? <UnifiedFeedSearch /> : <FeedPanels selected={selected as FeedTab} newsRegion={region} />}
    </div>
  </FeedPreviewProvider></FeedExperience>;
}

export function ThreatFeedShell({ region }: { region?: FeedRegion }) {
  return <Suspense fallback={<LoadingRows search rows={5} label="Loading threat feed…" />}><FeedTabs region={region} /></Suspense>;
}
