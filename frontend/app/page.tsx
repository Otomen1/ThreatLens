"use client";

import { useCallback, useEffect, useRef, useState } from "react";

import { investigateBatch, type BatchInvestigationResponse, type InvestigationResponse } from "@/lib/api";
import { InvestigationWorkspace } from "@/components/InvestigationWorkspace";

export default function HomePage() {
  const [query, setQuery] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<InvestigationResponse | null>(null);
  const [batch, setBatch] = useState<BatchInvestigationResponse | null>(null);
  const [expandedIoc, setExpandedIoc] = useState<number | null>(null);
  const [timestamp, setTimestamp] = useState("");
  const [stage, setStage] = useState("Preparing investigation…");
  const abortRef = useRef<AbortController | null>(null);

  // Cancel any in-flight request on unmount.
  useEffect(() => () => abortRef.current?.abort(), []);

  const runSearch = useCallback(async () => {
    const trimmed = query.trim();
    if (!trimmed) return;

    // A new search supersedes any in-flight one.
    abortRef.current?.abort();
    const controller = new AbortController();
    abortRef.current = controller;

    setLoading(true);
    setStage("Finding indicators…");
    setError(null);
    setResult(null);
    setBatch(null);
    setExpandedIoc(null);
    try {
      setStage("Querying intelligence sources…");
      const res = await investigateBatch(trimmed, controller.signal);
      setStage("Building evidence assessment…");
      if (res.total === 1 && res.items[0]?.status === "completed" && res.items[0].investigation) {
        setResult(res.items[0].investigation);
      } else {
        setBatch(res);
      }
      setTimestamp(new Date().toLocaleString("en-US", {
        month: "short", day: "numeric", year: "numeric",
        hour: "2-digit", minute: "2-digit", second: "2-digit",
        hour12: false,
      }));
    } catch (err) {
      if (err instanceof DOMException && err.name === "AbortError") return;
      setError(err instanceof Error ? err.message : "Something went wrong.");
    } finally {
      // Only the most recent request clears the loading state.
      if (abortRef.current === controller) {
        setLoading(false);
        abortRef.current = null;
      }
    }
  }, [query]);

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
          {loading && <p className="mt-2 text-center text-[11px] text-zinc-600" role="status">{stage}</p>}
          <p className="mt-2 text-center text-[11px] text-zinc-600">Paste free-form notes or a list; ThreatLens extracts up to 20 supported IOCs. Press Enter to search, Shift+Enter for a new line.</p>
        </div>

        {/* Error */}
        {error && (
          <div
            role="alert"
            className="bg-red-500/10 border border-red-500/30 text-red-300 text-sm rounded-xl px-4 py-3 text-center"
          >
            {error}
          </div>
        )}

        {/* Entity type hints (shown before the first search) */}
        {!result && !batch && !error && (
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
      {result && !error && (
        <div className="w-full max-w-5xl mt-10">
          <InvestigationWorkspace data={result} timestamp={timestamp} />
        </div>
      )}

      {batch && !error && (
        <section className="w-full max-w-5xl mt-10 space-y-3" aria-label="Batch IOC results">
          <div className="flex items-baseline justify-between gap-3">
            <h2 className="text-lg font-semibold text-white">Batch results</h2>
            <p className="text-xs text-zinc-500">{batch.total} IOC{batch.total === 1 ? "" : "s"} extracted</p>
          </div>
          {batch.items.map((item, index) => {
            const investigation = item.investigation;
            const isExpanded = expandedIoc === index;
            const providers = investigation?.threat_intelligence.statistics.providers_ok ?? 0;
            return (
              <article key={`${item.entity.type}-${item.entity.normalized_value}`} className="overflow-hidden rounded-xl border border-zinc-800 bg-zinc-900/70">
                <button
                  type="button"
                  onClick={() => investigation && setExpandedIoc(isExpanded ? null : index)}
                  disabled={!investigation}
                  className="flex w-full items-center gap-4 px-5 py-4 text-left disabled:cursor-default"
                  aria-expanded={investigation ? isExpanded : undefined}
                >
                  <span className={`h-2.5 w-2.5 rounded-full ${item.status === "completed" ? "bg-emerald-400" : "bg-red-400"}`} />
                  <span className="min-w-0 flex-1">
                    <span className="block truncate font-mono text-sm text-zinc-100">{item.entity.normalized_value}</span>
                    <span className="mt-1 block text-xs uppercase tracking-wide text-zinc-500">{item.entity.type}</span>
                  </span>
                  {investigation ? <span className="text-right text-xs text-zinc-400">Posture {investigation.investigation_summary.posture} · {providers} provider{providers === 1 ? "" : "s"} available</span> : <span className="max-w-sm text-right text-xs text-red-300">{item.error ?? "Investigation failed."}</span>}
                  {investigation && <span className="text-zinc-500">{isExpanded ? "−" : "+"}</span>}
                </button>
                {isExpanded && investigation && <div className="border-t border-zinc-800 px-4 pb-4"><InvestigationWorkspace data={investigation} timestamp={timestamp} /></div>}
              </article>
            );
          })}
        </section>
      )}
    </main>
  );
}
