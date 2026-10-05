"use client";

import { Suspense, useRef } from "react";
import { useSearchParams } from "next/navigation";
import NewsFeed from "@/components/threat-feed/NewsFeed";
import { VulnerabilityFeed } from "@/components/threat-feed/VulnerabilityFeed";
import { PocFeed } from "@/components/threat-feed/PocFeed";
import { IocFeed } from "@/components/threat-feed/IocFeed";
import { FeedStatus } from "@/components/threat-feed/FeedStatus";
import { UnifiedFeedSearch } from "@/components/threat-feed/FeedWorkflow";
import { FeedHeader } from "@/components/threat-feed/FeedHeader";
import { SavedFeed } from "@/components/threat-feed/SavedFeed";
import { FeedFilters } from "@/components/threat-feed/FeedFilters";
import { LoadingRows } from "@/components/ui/Skeleton";
import { FeedViewNavigation } from "@/components/threat-feed/FeedViewNavigation";

function FeedTabs() {
  const params = useSearchParams();
  const headerRef = useRef<HTMLElement>(null);
  const selected = ["vulnerabilities", "poc", "iocs"].includes(params.get("tab") ?? "") ? params.get("tab") : "news";
  return <>
    <FeedHeader headerRef={headerRef} />
    <div className="threat-feed-frame">
    <div className="mx-auto max-w-6xl px-4">
      <FeedViewNavigation selected={selected} headerRef={headerRef} />
      <FeedStatus manualPoc={selected === "poc"} />
      {!params.has("view") && <FeedFilters poc={selected === "poc"} />}
    </div>
    {params.get("view") === "saved" ? <SavedFeed /> : params.get("view") === "search" ? <UnifiedFeedSearch /> : selected === "news" ? <NewsFeed /> : selected === "poc" ? <PocFeed /> : selected === "iocs" ? <IocFeed /> : <VulnerabilityFeed />}
    </div>
  </>;
}

export default function ThreatFeedPage() {
  return <Suspense fallback={<LoadingRows search rows={5} label="Loading threat feed…" />}><FeedTabs /></Suspense>;
}
