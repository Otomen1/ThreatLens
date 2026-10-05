"use client";
import { useCallback, useEffect, useState } from "react";
import { useSearchParams } from "next/navigation";
import { FeedParamsContext, FeedReadyContext, type FeedTab } from "./FeedPanelContext";
import NewsFeed from "./NewsFeed";
import { VulnerabilityFeed } from "./VulnerabilityFeed";
import { IocFeed } from "./IocFeed";
import { PocFeed } from "./PocFeed";

export function FeedPanels({ selected }: { selected: FeedTab }) {
  const params = useSearchParams();
  const key = params.toString();
  const [snapshots, setSnapshots] = useState<Partial<Record<FeedTab, string>>>({ [selected]: key });
  const [visible, setVisible] = useState<FeedTab>(selected);
  const done = useCallback((tab: FeedTab) => { if (tab === selected) setVisible(tab); }, [selected]);
  useEffect(() => { setSnapshots((previous) => previous[selected] === key ? previous : { ...previous, [selected]: key }); }, [selected, key]);
  const previous = visible !== selected;
  const tabs = new Set<FeedTab>([...Object.keys(snapshots) as FeedTab[], selected]);
  return <>
    {previous && <p role="status" className="mx-auto max-w-6xl px-4 pt-4 text-xs text-amber-200">Previous view · Loading {selected === "iocs" ? "IOC reports" : selected === "poc" ? "PoC & Tools" : selected}… Actions are paused until the selected view is ready.</p>}
    {[...tabs].map((tab) => <div key={tab} hidden={tab !== visible} inert={previous && tab === visible} className={tab === visible ? "ui-panel-enter" : undefined}>
      <FeedParamsContext.Provider value={new URLSearchParams(tab === selected ? key : snapshots[tab])}>
        <FeedReadyContext.Provider value={{ tab, done }}>
          {tab === "news" ? <NewsFeed /> : tab === "vulnerabilities" ? <VulnerabilityFeed /> : tab === "iocs" ? <IocFeed /> : <PocFeed />}
        </FeedReadyContext.Provider>
      </FeedParamsContext.Provider>
    </div>)}
  </>;
}
