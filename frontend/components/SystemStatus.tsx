"use client";

import { useEffect, useRef, useState } from "react";

import { aiHealth, health, type AIHealth, type HealthStatus } from "@/lib/api";

type State =
  | { kind: "loading" }
  | { kind: "online"; health: HealthStatus; ai: AIHealth | null }
  | { kind: "offline" };

/**
 * A passive, unobtrusive system-status indicator.
 *
 * On mount it performs the read-only liveness check (and a best-effort AI status
 * check) and renders a small pill: green when the backend is operational, gray
 * when it can't be reached. It never blocks or alters the app — if the health
 * endpoints are unavailable it simply shows "Offline". AI status is secondary
 * and can never flip the overall indicator (AI is optional).
 */
export function SystemStatus() {
  const [state, setState] = useState<State>({ kind: "loading" });
  const abortRef = useRef<AbortController | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    abortRef.current = controller;

    (async () => {
      try {
        const liveness = await health(controller.signal);
        // AI health is best-effort and must never mark the system offline.
        let ai: AIHealth | null = null;
        try {
          ai = await aiHealth(controller.signal);
        } catch {
          ai = null;
        }
        setState({ kind: "online", health: liveness, ai });
      } catch (err) {
        if (err instanceof DOMException && err.name === "AbortError") return;
        setState({ kind: "offline" });
      }
    })();

    return () => controller.abort();
  }, []);

  const { dotClass, label, title } = describe(state);

  return (
    <div className="fixed top-4 right-4 z-50">
      <div
        className="flex items-center gap-2 rounded-full border border-zinc-800 bg-zinc-900/70 px-3 py-1.5 backdrop-blur-sm"
        role="status"
        aria-label={title}
        title={title}
      >
        <span className={`h-2 w-2 rounded-full ${dotClass}`} aria-hidden />
        <span className="text-[11px] font-medium text-zinc-400">{label}</span>
        {state.kind === "online" && <AIBadge ai={state.ai} />}
      </div>
    </div>
  );
}

/** A secondary AI indicator, shown only when the AI layer is enabled. */
function AIBadge({ ai }: { ai: AIHealth | null }) {
  if (!ai || !ai.enabled) return null;
  const ok = ai.status === "ok";
  return (
    <span className="flex items-center gap-1 border-l border-zinc-800 pl-2">
      <span
        className={`h-1.5 w-1.5 rounded-full ${ok ? "bg-emerald-500" : "bg-amber-500"}`}
        aria-hidden
      />
      <span className="text-[11px] text-zinc-500">AI</span>
    </span>
  );
}

function describe(state: State): { dotClass: string; label: string; title: string } {
  switch (state.kind) {
    case "online":
      return {
        dotClass: "bg-emerald-500",
        label: "Operational",
        title: `ThreatLens v${state.health.version} · operational`,
      };
    case "offline":
      return {
        dotClass: "bg-zinc-600",
        label: "Offline",
        title: "Backend service is unreachable",
      };
    default:
      return {
        dotClass: "bg-zinc-600 animate-pulse",
        label: "Checking…",
        title: "Checking system status",
      };
  }
}
