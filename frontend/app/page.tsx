"use client";

import { useCallback, useEffect, useRef, useState } from "react";

import { BatchWorkspace } from "@/components/batch/BatchWorkspace";
import { InvestigationWorkspace } from "@/components/InvestigationWorkspace";
import { useBatchInvestigation } from "@/hooks/useBatchInvestigation";

export default function HomePage() {
  const searchRef = useRef<HTMLTextAreaElement>(null);
  const [query, setQuery] = useState(() => {
    if (typeof window === "undefined") return "";
    return new URLSearchParams(window.location.search).get("q") ?? "";
  });
  const [timestamp, setTimestamp] = useState("");
  const [scanMode, setScanMode] = useState<"fast" | "standard" | "full">("standard");
  const [excludedProviders, setExcludedProviders] = useState<string[]>([]);
  const batch = useBatchInvestigation();
  const loading = batch.previewing || batch.running;
  const result = batch.preview?.entities.length === 1 ? batch.rows[0]?.investigation ?? null : null;

  useEffect(() => {
    if (new URLSearchParams(window.location.search).get("focus") === "search") searchRef.current?.focus();
  }, []);

  const runSearch = useCallback(async () => {
    const trimmed = query.trim();
    if (!trimmed) return;

    await batch.prepare(trimmed, { scanMode, excludedProviders });
    setTimestamp(new Date().toLocaleString("en-US", { month: "short", day: "numeric", year: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false }));
  }, [query, batch, scanMode, excludedProviders]);

  return (
    <main className="min-h-screen flex flex-col items-center px-4 py-12 sm:py-20">
      {/* Search controls — kept narrow */}
      <div className="w-full max-w-2xl space-y-8">
        {/* Logo + heading */}
        <div className="text-center space-y-3">
          <div className="inline-flex items-center justify-center w-12 h-12 rounded-xl bg-zinc-800 border border-zinc-700 mb-2">
            <svg
              width="24"
              height="24"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.5"
              strokeLinecap="round"
              strokeLinejoin="round"
              className="text-zinc-300"
            >
              <circle cx="11" cy="11" r="8" />
              <path d="m21 21-4.35-4.35" />
              <path d="M11 8v6M8 11h6" />
            </svg>
          </div>
          <h1 className="text-3xl font-semibold text-white tracking-tight">
            ThreatLens
          </h1>
          <p className="text-zinc-500 text-sm leading-relaxed max-w-md mx-auto">
            Search any indicator, technique, actor, or vulnerability.
            <br />
            Understand it instantly.
          </p>
        </div>

        {/* Search box */}
        <div className="relative">
          <div className="flex items-center bg-zinc-900 border border-zinc-800 rounded-2xl overflow-hidden transition-colors focus-within:border-zinc-600">
            <svg
              width="16"
              height="16"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
              className="absolute left-5 text-zinc-600 shrink-0"
            >
              <circle cx="11" cy="11" r="8" />
              <path d="m21 21-4.35-4.35" />
            </svg>
            <textarea
              ref={searchRef}
              data-focus="search"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && !e.shiftKey) {
                  e.preventDefault();
                  runSearch();
                }
              }}
              placeholder="Paste one or more IOCs — IPs, domains, URLs, hashes…"
              aria-label="Search one or more IOCs"
              autoFocus
              spellCheck={false}
              autoComplete="off"
              rows={3}
              className="w-full resize-y bg-transparent pl-12 pr-28 py-4 text-white placeholder-zinc-700 text-sm focus:outline-none font-mono"
            />
            <button
              onClick={runSearch}
              disabled={loading || !query.trim()}
              className="absolute right-3 bg-zinc-800 hover:bg-zinc-700 border border-zinc-700 text-zinc-300 text-xs font-medium px-4 py-2 rounded-xl transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading ? "Searching…" : "Search"}
            </button>
          </div>
          {loading && <p className="mt-2 text-center text-[11px] text-zinc-600" role="status">{batch.previewing ? "Finding indicators…" : "Querying intelligence sources…"}</p>}
          <p className="mt-2 text-center text-[11px] text-zinc-600">Paste free-form notes or a list; ThreatLens extracts up to 20 supported IOCs. Press Enter to search, Shift+Enter for a new line.</p>
        </div>

        <div className="flex flex-wrap items-center justify-center gap-3 text-xs">
          <label className="text-zinc-500">Scan mode <select value={scanMode} onChange={(event) => setScanMode(event.target.value as typeof scanMode)} className="ml-2 rounded-lg border border-zinc-800 bg-zinc-900 px-3 py-2 text-zinc-200"><option value="fast">Fast</option><option value="standard">Standard</option><option value="full">Full</option></select></label>
          <details className="relative"><summary className="cursor-pointer rounded-lg border border-zinc-800 px-3 py-2 text-zinc-400">Provider exclusions ({excludedProviders.length})</summary><div className="absolute right-0 z-20 mt-2 w-52 space-y-2 rounded-xl border border-zinc-800 bg-zinc-950 p-3 shadow-xl">{["malwarebazaar", "urlhaus", "abuseipdb", "otx", "virustotal"].map((provider) => <label key={provider} className="flex items-center gap-2 text-zinc-300"><input type="checkbox" checked={excludedProviders.includes(provider)} onChange={(event) => setExcludedProviders((current) => event.target.checked ? [...current, provider] : current.filter((item) => item !== provider))} />{provider}</label>)}</div></details>
        </div>

        {batch.recoverable && !batch.preview && <div className="rounded-xl border border-sky-500/30 bg-sky-500/10 p-4 text-sm text-sky-200"><p>A previous batch can be recovered.</p><div className="mt-3 flex gap-2"><button onClick={batch.resume} className="rounded-lg bg-sky-600 px-3 py-2 text-xs text-white">Resume previous batch</button><button onClick={batch.discardRecovery} className="rounded-lg border border-sky-500/30 px-3 py-2 text-xs">Discard</button></div></div>}

        {/* Error */}
        {batch.error && (
          <div
            role="alert"
            className="bg-red-500/10 border border-red-500/30 text-red-300 text-sm rounded-xl px-4 py-3 text-center"
          >
            {batch.error}
          </div>
        )}

        {/* Entity type hints (shown before the first search) */}
        {!result && !batch.preview && !batch.error && (
          <div className="flex flex-wrap justify-center gap-2">
            {[
              "IP Address",
              "Domain",
              "File Hash",
              "CVE",
              "MITRE Technique",
              "Malware Family",
              "Threat Actor",
              "Registry Key",
            ].map((type) => (
              <span
                key={type}
                className="px-3 py-1 bg-zinc-900 border border-zinc-800 rounded-full text-zinc-600 text-xs"
              >
                {type}
              </span>
            ))}
          </div>
        )}
      </div>

      {/* Investigation workspace — wider than the search box */}
      {result && !batch.error && (
        <div className="w-full max-w-5xl mt-10">
          <div className="mb-3 flex flex-wrap items-center gap-2 rounded-xl border border-zinc-800 bg-zinc-900 p-3 text-xs text-zinc-400"><span className={result.cache.status === "hit" ? "text-emerald-300" : "text-zinc-300"}>{result.cache.status === "hit" ? `Cached result · ${result.cache.age_seconds ?? 0}s old` : result.cache.status === "refreshed" ? "Freshly refreshed" : "Fresh provider result"}</span><span>· {result.scan_mode} scan · {result.routed_providers.length} TI providers</span><button onClick={() => void batch.prepare(query.trim(), { scanMode, excludedProviders, refresh: true })} className="ml-auto underline text-sky-300">Refresh now</button></div>
          <InvestigationWorkspace data={result} timestamp={timestamp} onInvestigateRelated={(related) => { setQuery(related); void batch.prepare(related, { scanMode: "standard" }); }} />
        </div>
      )}

      {batch.preview?.entities.length === 1 && batch.rows[0]?.state === "failed" && (
        <div role="alert" className="mt-10 rounded-xl border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-300">
          {batch.rows[0].error}
          {batch.rows[0].retryable && <button type="button" onClick={() => void batch.retry([0])} className="ml-3 underline">Retry</button>}
        </div>
      )}

      {batch.preview && batch.preview.entities.length > 1 && !batch.error && <BatchWorkspace preview={batch.preview} rows={batch.rows} setRows={batch.setRows} running={batch.running} timestamp={timestamp} onStart={(entities) => void batch.start(entities)} onRetry={(indexes) => void batch.retry(indexes)} onCancel={batch.cancel} onClear={batch.clear} />}
    </main>
  );
}
