"use client";
import { createContext, useContext, useEffect } from "react";
import { useSearchParams } from "next/navigation";

export type FeedTab = "news" | "vulnerabilities" | "iocs" | "poc";
export const FeedParamsContext = createContext<URLSearchParams | null>(null);
export const FeedReadyContext = createContext<{ tab: FeedTab; done: (tab: FeedTab) => void } | null>(null);
export function useFeedParams() {
  const current = useSearchParams();
  return useContext(FeedParamsContext) ?? current;
}
export function useFeedReady(ready: boolean) {
  const context = useContext(FeedReadyContext);
  const done = context?.done, tab = context?.tab;
  useEffect(() => { if (ready && done && tab) done(tab); }, [ready, done, tab]);
}
