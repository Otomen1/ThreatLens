"use client";

import { Suspense, useRef, useState } from "react";
import { useSearchParams } from "next/navigation";
import NewsFeed from "@/components/threat-feed/NewsFeed";
import { VulnerabilityFeed } from "@/components/threat-feed/VulnerabilityFeed";
import { PocFeed } from "@/components/threat-feed/PocFeed";
import { IocFeed } from "@/components/threat-feed/IocFeed";
import { FeedStatus } from "@/components/threat-feed/FeedStatus";
import { FeedSearchBox, UnifiedFeedSearch } from "@/components/threat-feed/FeedWorkflow";
import { SavedFeed } from "@/components/threat-feed/SavedFeed";
import { FeedFilters } from "@/components/threat-feed/FeedFilters";
import { LoadingRows } from "@/components/ui/Skeleton";
import { FeedViewNavigation } from "@/components/threat-feed/FeedViewNavigation";

function FeedTabs() {
  const params = useSearchParams();
  const headerRef = useRef<HTMLElement>(null);
  const [docked, setDocked] = useState(false);
  const selected = ["vulnerabilities", "poc", "iocs"].includes(params.get("tab") ?? "") ? params.get("tab") : "news";
  return <>
    <header ref={headerRef} aria-label="Threat Feed search controls" className="sticky top-14 z-30 border-b border-zinc-800 bg-zinc-950">
      <div className="mx-auto max-w-6xl px-4 py-4 sm:py-6">
        <h1 className="text-3xl font-semibold">Threat Feed</h1>
        <FeedSearchBox />
      </div>
    </header>
    <div className={`transition-[padding] duration-200 ${docked ? "lg:pl-40" : ""}`}>
    <div className="mx-auto max-w-6xl px-4">
      <FeedViewNavigation selected={selected} headerRef={headerRef} onDockChange={setDocked} />
      <FeedStatus manualPoc={selected === "poc"} />
      {!params.has("view") && <FeedFilters poc={selected === "poc"} />}
    </div>
    {params.get("view") === "saved" ? <SavedFeed /> : params.get("view") === "search" ? <UnifiedFeedSearch /> : selected === "news" ? <NewsFeed /> : selected === "poc" ? <PocFeed /> : selected === "iocs" ? <IocFeed /> : <VulnerabilityFeed />}
    </div>
  </>;
}

export default function ThreatFeedPage() {
  return <Suspense fallback={<LoadingRows rows={5} label="Loading threat feed" />}><FeedTabs /></Suspense>;
}
