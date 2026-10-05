"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useFeedParams, useFeedReady } from "./FeedPanelContext";
import { useCallback, useEffect, useRef, useState } from "react";
import { createClient } from "@/lib/supabase/browser";
import { ApiError } from "@/lib/api/client";
import { lookupPoc, normalizePocCve, type PocSource, type PocSourceResult } from "@/lib/api/poc";
import { LoadingRows } from "@/components/ui/Skeleton";

const sources: PocSource[] = ["metasploit", "nuclei"];
const labels = { metasploit: "Metasploit", nuclei: "Nuclei" };
const control = "rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm focus-visible:outline focus-visible:outline-sky-400 disabled:opacity-40";
type SourceState = { checking: boolean; result?: PocSourceResult; error?: string };

export function PocFeed() {
  const params = useFeedParams();
  useFeedReady(true);
  const router = useRouter();
  const [input, setInput] = useState(params.get("cve") ?? "");
  const [signedIn, setSignedIn] = useState<boolean | null>(null);
  const [states, setStates] = useState<Partial<Record<PocSource, SourceState>>>({});
  const [submitted, setSubmitted] = useState("");
  const [notice, setNotice] = useState("");
  const controllers = useRef<Partial<Record<PocSource, AbortController>>>({});
  const generation = useRef(0);
  const activeCve = useRef("");
  const signed = useRef(false);
  const urlCve = params.get("cve") ?? "";
  const cancelRequests = useCallback(() => {
    generation.current++;
    Object.values(controllers.current).forEach((controller) => controller.abort());
  }, []);

  useEffect(() => {
    const client = createClient();
    let active = true;
    const update = (value: boolean) => {
      if (!active) return;
      signed.current = value;
      setSignedIn(value);
      if (!value) {
        generation.current++;
        Object.values(controllers.current).forEach((controller) => controller.abort());
        setStates({});
        setSubmitted("");
        activeCve.current = "";
      }
    };
    client.auth.getSession().then(({ data }) => update(Boolean(data.session))).catch(() => update(false));
    const { data } = client.auth.onAuthStateChange((_event, session) => update(Boolean(session)));
    return () => {
      active = false;
      data.subscription.unsubscribe();
      cancelRequests();
    };
  }, [cancelRequests]);

  useEffect(() => {
    setInput(urlCve);
    if (activeCve.current && urlCve !== activeCve.current) {
      generation.current++;
      Object.values(controllers.current).forEach((controller) => controller.abort());
      activeCve.current = "";
      setSubmitted("");
      setStates({});
    }
  }, [urlCve]);

  function updateFilter(name: string, value: string) {
    const next = new URLSearchParams(params.toString());
    value ? next.set(name, value) : next.delete(name);
    router.replace(`/threat-feed?${next}`, { scroll: false });
  }

  async function runSource(source: PocSource, cve: string, fresh: boolean, id: number) {
    controllers.current[source]?.abort();
    const controller = new AbortController();
    controllers.current[source] = controller;
    const timeout = setTimeout(() => controller.abort(), 25_000);
    setStates((current) => ({ ...current, [source]: { ...current[source], checking: true, error: undefined } }));
    try {
      const result = await lookupPoc(source, cve, fresh, controller.signal);
      if (id === generation.current && signed.current && controllers.current[source] === controller) setStates((current) => ({ ...current, [source]: { checking: false, result } }));
    } catch (error) {
      if (id !== generation.current || !signed.current || controllers.current[source] !== controller) return;
      const message = error instanceof ApiError && error.status === 401 ? "Please sign in again." : controller.signal.aborted ? "Source lookup timed out. Retry manually." : "Source lookup is unavailable. Retry manually.";
      setStates((current) => ({ ...current, [source]: { ...current[source], checking: false, error: message } }));
    } finally { clearTimeout(timeout); }
  }

  function search(fresh = false) {
    const cve = normalizePocCve(fresh ? submitted : input);
    if (!signedIn || !cve) { setNotice("Enter one valid CVE, for example CVE-2021-44228."); return; }
    generation.current++;
    Object.values(controllers.current).forEach((controller) => controller.abort());
    activeCve.current = cve;
    setSubmitted(cve);
    setInput(cve);
    setNotice("");
    if (!fresh || submitted !== cve) setStates({});
    const next = new URLSearchParams(params.toString());
    next.set("tab", "poc"); next.set("cve", cve);
    router.replace(`/threat-feed?${next}`, { scroll: false });
    sources.forEach((source) => void runSource(source, cve, fresh, generation.current));
  }

  const checking = sources.some((source) => states[source]?.checking);
  const tool = params.get("tool") ?? "";
  const kind = params.get("kind") ?? "";
  const matches = sources.flatMap((source) => states[source]?.result?.matches ?? []).filter((item) => (!tool || item.source === tool) && (!kind || item.kind === kind));
  return <main className="mx-auto min-h-screen max-w-6xl space-y-5 px-4 py-8">
    <p className="max-w-3xl text-sm text-zinc-400">Search official Metasploit and Nuclei metadata for exact CVE references. Nothing is installed, downloaded as executable code, or run against a target.</p>
    <div className="rounded-xl border border-amber-500/20 bg-amber-500/5 p-4 text-xs leading-5 text-amber-200">CVE reference confirmed means the official metadata lists that CVE. It does not confirm a working exploit, a vulnerable system, or safety. Every resource is not locally tested. Nuclei templates are detection resources and are not necessarily passive or harmless.</div>
    {signedIn === null ? <p role="status" className="text-sm text-zinc-500">Checking sign-in…</p> : !signedIn ? <div className="rounded-xl border border-zinc-800 p-5"><p className="text-sm text-zinc-400">Sign in to perform online PoC lookups. No source requests are made while signed out.</p><Link href={`/login?next=${encodeURIComponent(`/threat-feed?tab=poc${urlCve ? `&cve=${encodeURIComponent(urlCve)}` : ""}`)}`} className="mt-3 inline-block text-sm text-sky-300 hover:underline">Sign in for PoC lookup</Link></div> : <>
      <form onSubmit={(event) => { event.preventDefault(); search(); }} className="flex flex-col gap-3 sm:flex-row"><label className="flex-1"><span className="sr-only">CVE identifier</span><input className={`${control} w-full`} value={input} onChange={(event) => setInput(event.target.value)} maxLength={32} placeholder="CVE-2021-44228" /></label><button className={control} type="submit">Search</button><button className={control} type="button" disabled={!submitted || checking} onClick={() => search(true)}>Check latest</button></form>
      <p className="text-xs text-zinc-500">Temporary: lookup results stay in browser memory only. Source cache age and stale fallback are shown separately.</p>
      {notice && <p role="alert" className="text-sm text-amber-300">{notice}</p>}
      {submitted && <>
        <p role="status" aria-live="polite" className="text-sm text-zinc-500">{submitted} · {checking ? "Checking sources; results appear independently…" : "Source checks finished."}</p>
        <div className="grid gap-3 sm:grid-cols-2">{sources.map((source) => {
          const state = states[source]; const result = state?.result;
          return <section key={source} aria-label={`${labels[source]} source status`} className="rounded-xl border border-zinc-800 bg-zinc-900/40 p-4">
            <h2 className="font-medium">{labels[source]}</h2><p role="status" className="mt-2 text-sm text-zinc-400">{state?.checking ? "Checking…" : state?.error ?? result?.message ?? "Queued"}</p>
            {result && <p className="mt-2 text-xs text-zinc-500">{result.stale ? "Stale fallback" : result.cached ? "Temporary cached metadata" : "Online metadata"} · Checked {new Date(result.checked_at).toLocaleString()}{result.cache_age_seconds !== null && ` · ${result.cache_age_seconds}s old`}{result.next_eligible_at && ` · Retry after ${new Date(result.next_eligible_at).toLocaleTimeString()}`}</p>}
            {result?.truncated && <p className="mt-2 text-xs text-amber-200">Showing the first 100 of {result.total_matches} matches.</p>}
            {!!result?.skipped_records && <p className="mt-2 text-xs text-amber-200">{result.skipped_records} malformed metadata records skipped; coverage may be incomplete.</p>}
            {!state?.checking && (state?.error || result?.retryable) && <button className={`${control} mt-3`} onClick={() => void runSource(source, submitted, true, generation.current)}>Retry {labels[source]}</button>}
          </section>;
        })}</div>
        <div className="flex flex-wrap gap-3"><select aria-label="PoC tool filter" className={control} value={tool} onChange={(event) => updateFilter("tool", event.target.value)}><option value="">All tools</option><option value="metasploit">Metasploit</option><option value="nuclei">Nuclei</option></select><select aria-label="PoC resource type" className={control} value={kind} onChange={(event) => updateFilter("kind", event.target.value)}><option value="">All resource types</option><option value="exploit">Exploit module</option><option value="auxiliary">Auxiliary module</option><option value="detection">Detection template</option><option value="other">Other module</option></select></div>
        {matches.length ? <div role="table" aria-label="Official PoC and tools matches" className="space-y-3">
          <div role="row" className="hidden gap-3 px-4 text-xs text-zinc-500 md:grid md:grid-cols-[1fr_160px_190px]"><span role="columnheader">Resource / source link</span><span role="columnheader">Tool / type / platform</span><span role="columnheader">Source dates / verification</span></div>
          {matches.map((item) => <div role="row" key={`${item.source}:${item.id}`} className="grid gap-3 rounded-xl border border-zinc-800 p-4 md:grid-cols-[1fr_160px_190px]">
          <div role="cell"><a className="text-sm font-medium text-sky-300 hover:underline focus-visible:outline focus-visible:outline-sky-400" href={item.url} target="_blank" rel="noreferrer">{item.name} ↗</a><p className="mt-1 break-all font-mono text-xs text-zinc-500">{item.path}</p><p className="mt-2 text-xs leading-5 text-zinc-400">{item.description || "Not supplied"}</p></div>
          <div role="cell" className="space-y-2 text-xs text-zinc-400"><p>{labels[item.source]}</p><p>{item.kind === "detection" ? "Detection template" : `${item.module_type ?? "Other"} module`}</p><p>Platform: {item.platforms.join(", ") || "Not supplied"}</p>{item.severity && <p>Source severity: {item.severity}</p>}<p>Check support: {item.check_supported === null ? "Not supplied" : item.check_supported ? "Source reports yes" : "Source reports no"}</p></div>
          <div role="cell" className="space-y-2 text-xs text-zinc-500"><p>Disclosed: {item.disclosure_date ?? "Not supplied"}</p><p>Modified: {item.modified_at ?? "Not supplied"}</p><p className="text-emerald-300">CVE reference confirmed</p><p>Official repository source</p><p className="text-amber-200">Not locally tested</p></div>
        </div>)}</div> : checking ? <LoadingRows rows={3} label="Checking PoC sources" /> : <p className="rounded-xl border border-zinc-800 p-6 text-sm text-zinc-500">No matching resources to display. Check the source statuses and selected filters; unavailable sources are not evidence that no PoC exists.</p>}
      </>}
    </>}
  </main>;
}
