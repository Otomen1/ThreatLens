"use client";

import Link from "next/link";
import { useEffect, useRef, useState } from "react";

import { correlationFrameworkStatus, type CorrelationFrameworkStatus } from "@/lib/api";

type State =
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "ready"; status: CorrelationFrameworkStatus };

export default function CorrelationPage() {
  const [state, setState] = useState<State>({ kind: "loading" });
  const abortRef = useRef<AbortController | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    abortRef.current = controller;

    (async () => {
      try {
        const status = await correlationFrameworkStatus(controller.signal);
        setState({ kind: "ready", status });
      } catch (err) {
        if (err instanceof DOMException && err.name === "AbortError") return;
        setState({
          kind: "error",
          message: err instanceof Error ? err.message : "Could not reach the service.",
        });
      }
    })();

    return () => controller.abort();
  }, []);

  return (
    <main className="min-h-screen px-4 py-10 sm:py-14">
      <div className="w-full max-w-2xl mx-auto space-y-6">
        <header>
          <Link href="/" className="text-xs text-zinc-500 hover:text-zinc-300 transition-colors">
            ← Back to Search
          </Link>
          <h1 className="text-2xl font-semibold text-white tracking-tight mt-1">
            Investigation Correlation
          </h1>
          <p className="text-zinc-500 text-sm mt-1">
            Deterministically combines an investigation&apos;s existing findings into higher-level
            observations. Only combines evidence, never invents it — no AI, no scoring.
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
          <div className="bg-zinc-900 border border-zinc-800 rounded-2xl p-6 space-y-5">
            <div className="flex items-center gap-2">
              <span className="h-2 w-2 rounded-full bg-emerald-400" aria-hidden />
              <span className="text-sm font-semibold text-white">Engine Ready</span>
            </div>

            <dl className="space-y-3 text-sm">
              <div className="flex items-center justify-between gap-4">
                <dt className="text-zinc-500">Registered Rules</dt>
                <dd className="text-zinc-300">{state.status.rules_registered}</dd>
              </div>
              <div className="flex items-center justify-between gap-4">
                <dt className="text-zinc-500">Architecture Version</dt>
                <dd className="text-zinc-300 font-mono">{state.status.framework_version}</dd>
              </div>
            </dl>

            <p className="text-xs text-zinc-600 leading-relaxed pt-2 border-t border-zinc-800">
              This is an architecture preview. The engine ships a small seed rule set and is not yet
              wired into an investigation — deterministic correlation of findings arrives in a future
              phase.
            </p>
          </div>
        )}
      </div>
    </main>
  );
}
