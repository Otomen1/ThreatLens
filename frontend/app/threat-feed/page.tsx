"use client";

import { Suspense } from "react";
import Link from "next/link";
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

function FeedTabs() {
  const params = useSearchParams();
  const selected = ["vulnerabilities", "poc", "iocs"].includes(params.get("tab") ?? "") ? params.get("tab") : "news";
  return <>
    <header aria-label="Threat Feed search controls" className="sticky top-14 z-30 border-b border-zinc-800 bg-zinc-950">
      <div className="mx-auto max-w-6xl px-4 py-4 sm:py-6">
        <h1 className="text-3xl font-semibold">Threat Feed</h1>
        <FeedSearchBox />
      </div>
    </header>
    <div className="mx-auto max-w-6xl px-4">
      <nav aria-label="Threat Feed views" className="mt-6 flex flex-wrap gap-2 border-b border-zinc-800 pb-3">
        {(["news", "vulnerabilities", "poc", "iocs"] as const).map((tab) => <Link key={tab}
          aria-current={selected === tab ? "page" : undefined}
          className={`rounded-lg px-4 py-2 text-sm capitalize focus-visible:outline focus-visible:outline-sky-400 ${selected === tab ? "bg-zinc-800 text-white" : "text-zinc-400 hover:bg-zinc-900"}`}
          href={`/threat-feed?tab=${tab}`}>{tab === "poc" ? "PoC & Tools" : tab === "iocs" ? "IOC Reports" : tab}</Link>)}
      </nav>
      <FeedStatus manualPoc={selected === "poc"} />
      {!params.has("view") && <FeedFilters poc={selected === "poc"} />}
    </div>
    {params.get("view") === "saved" ? <SavedFeed /> : params.get("view") === "search" ? <UnifiedFeedSearch /> : selected === "news" ? <NewsFeed /> : selected === "poc" ? <PocFeed /> : selected === "iocs" ? <IocFeed /> : <VulnerabilityFeed />}
  </>;
}

export default function ThreatFeedPage() {
  return <Suspense fallback={<LoadingRows rows={5} label="Loading threat feed" />}><FeedTabs /></Suspense>;
}
