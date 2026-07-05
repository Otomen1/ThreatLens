"use client";

import Link from "next/link";
import { useCallback, useEffect, useRef, useState } from "react";

import { exposureFrameworkStatus, type ExposureFrameworkStatus } from "@/lib/api";
import { ExposureFindingCard } from "@/components/exposure/ExposureFindingCard";

type State =
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "ready"; status: ExposureFrameworkStatus };

const PROVIDER_STATUS_DOT: Record<string, string> = {
  operational: "bg-emerald-400",
  degraded: "bg-amber-400",
  unavailable: "bg-red-400",
  disabled: "bg-zinc-600",
  unknown: "bg-zinc-600",
};

const PROVIDER_STATUS_LABEL: Record<string, string> = {
  operational: "Operational",
  degraded: "Degraded",
  unavailable: "Unavailable",
  disabled: "Disabled",
  unknown: "Unknown",
};

export default function ExposurePage() {
  const [state, setState] = useState<State>({ kind: "loading" });
  const [query, setQuery] = useState("");
  const [searching, setSearching] = useState(false);
  const abortRef = useRef<AbortController | null>(null);

  const load = useCallback(async (value?: string) => {
    abortRef.current?.abort();
    const controller = new AbortController();
    abortRef.current = controller;

    if (value) {
      setSearching(true);
    } else {
      setState({ kind: "loading" });
    }

    try {
      const status = await exposureFrameworkStatus(value, controller.signal);
      setState({ kind: "ready", status });
    } catch (err) {
      if (err instanceof DOMException && err.name === "AbortError") return;
      setState({
        kind: "error",
        message: err instanceof Error ? err.message : "Could not reach the service.",
      });
    } finally {
      if (abortRef.current === controller) {
        setSearching(false);
        abortRef.current = null;
      }
    }
  }, []);

  useEffect(() => {
    load();
    return () => abortRef.current?.abort();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const runSearch = () => {
    const trimmed = query.trim();
    if (!trimmed) return;
    load(trimmed);
  };

  const summary = state.kind === "ready" ? state.status.summary : null;

  return (
    <main className="min-h-screen px-4 py-10 sm:py-14">
      <div className="w-full max-w-3xl mx-auto space-y-6">
        <header>
          <Link href="/" className="text-xs text-zinc-500 hover:text-zinc-300 transition-colors">
            ← Back to Search
          </Link>
          <h1 className="text-2xl font-semibold text-white tracking-tight mt-1">
            Exposure Intelligence
          </h1>
          <p className="text-zinc-500 text-sm mt-1">
            Where is this entity exposed — open ports, certificates, hosting. Descriptive only,
            never a maliciousness verdict.
          </p>
        </header>

        {state.kind === "loading" && (
          <div className="bg-zinc-900 border border-zinc-800 rounded-2xl p-8 text-center text-sm text-zinc-500">
            Checking framework status…
          </div>
        )}

        {state.kind === "error" && (
          <div
            role="alert"
            className="bg-red-500/10 border border-red-500/30 text-red-300 text-sm rounded-xl px-4 py-3"
          >
            {state.message}
          </div>
        )}

        {state.kind === "ready" && (
          <>
            {/* Provider status */}
            <div className="bg-zinc-900 border border-zinc-800 rounded-2xl p-6 space-y-5">
              <div className="flex items-center gap-2">
                <span className="h-2 w-2 rounded-full bg-emerald-400" aria-hidden />
                <span className="text-sm font-semibold text-white">Provider Status</span>
              </div>

              <dl className="space-y-3 text-sm">
                <div className="flex items-center justify-between gap-4">
                  <dt className="text-zinc-500">Framework Version</dt>
                  <dd className="text-zinc-300 font-mono">{state.status.framework_version}</dd>
                </div>
                <div className="flex items-center justify-between gap-4">
                  <dt className="text-zinc-500">Provider Count</dt>
                  <dd className="text-zinc-300">{state.status.providers_registered}</dd>
                </div>
                {state.status.providers.map((provider) => (
                  <div key={provider.name} className="flex items-center justify-between gap-4">
                    <dt className="text-zinc-500">{provider.display_name} Status</dt>
                    <dd className="flex items-center gap-2 text-right">
                      <span
                        className={`h-1.5 w-1.5 rounded-full shrink-0 ${
                          PROVIDER_STATUS_DOT[provider.status] ?? "bg-zinc-600"
                        }`}
                        aria-hidden
                      />
                      <span className="text-zinc-300">
                        {PROVIDER_STATUS_LABEL[provider.status] ?? provider.status}
                      </span>
                      {provider.detail && (
                        <span className="text-zinc-600 text-xs">({provider.detail})</span>
                      )}
                    </dd>
                  </div>
                ))}
              </dl>

              {state.status.providers.length === 0 && (
                <p className="text-xs text-zinc-600 leading-relaxed pt-2 border-t border-zinc-800">
                  No providers installed yet.
                </p>
              )}
            </div>

            {/* Search */}
            <div className="bg-zinc-900 border border-zinc-800 rounded-2xl p-6 space-y-3">
              <div className="flex items-center bg-zinc-950 border border-zinc-800 rounded-xl overflow-hidden focus-within:border-zinc-600 transition-colors">
                <input
                  type="text"
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") runSearch();
                  }}
                  placeholder="8.8.8.8"
                  aria-label="IP address to look up"
                  spellCheck={false}
                  autoComplete="off"
                  className="w-full bg-transparent px-4 py-3 text-white placeholder-zinc-700 text-sm focus:outline-none font-mono"
                />
                <button
                  onClick={runSearch}
                  disabled={searching || !query.trim()}
                  className="m-1.5 bg-zinc-800 hover:bg-zinc-700 border border-zinc-700 text-zinc-300 text-xs font-medium px-4 py-2 rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed shrink-0"
                >
                  {searching ? "Looking up…" : "Look up"}
                </button>
              </div>
              <p className="text-xs text-zinc-600">
                IPv4/IPv6 only today (Shodan). Results are descriptive facts, never a verdict.
              </p>
            </div>

            {/* Results */}
            {summary && (
              <div className="bg-zinc-900 border border-zinc-800 rounded-2xl p-6 space-y-4">
                <div className="flex items-center justify-between gap-4">
                  <h2 className="text-sm font-semibold text-white truncate">
                    Exposure for {summary.entity_value}
                  </h2>
                  <span className="text-xs text-zinc-500 shrink-0">
                    {summary.statistics.total_findings} finding(s) · {summary.statistics.total_assets}{" "}
                    asset(s)
                  </span>
                </div>

                {summary.findings.length === 0 && (
                  <p className="text-sm text-zinc-500">
                    {state.status.providers_registered === 0
                      ? "No exposure providers are configured."
                      : `No exposure providers support "${summary.entity_type}" entities, or all are disabled.`}
                  </p>
                )}

                <div className="space-y-2">
                  {summary.findings.map((finding) => (
                    <ExposureFindingCard key={finding.provider} finding={finding} />
                  ))}
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </main>
  );
}
