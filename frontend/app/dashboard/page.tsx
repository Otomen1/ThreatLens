"use client";

import Link from "next/link";
import { useCallback, useEffect, useRef, useState } from "react";

import {
  systemConfig,
  systemHealth,
  systemUsage,
  type ConfigStatusResponse,
  type SystemHealthResponse,
  type UsageResponse,
} from "@/lib/api";
import { formatTimestamp } from "@/lib/dashboard";
import { ApiConsumptionTab } from "@/components/dashboard/ApiConsumptionTab";
import { ConfigurationTab } from "@/components/dashboard/ConfigurationTab";
import { DashboardTabs } from "@/components/dashboard/DashboardTabs";
import { SystemHealthTab } from "@/components/dashboard/SystemHealthTab";

// Read-only: refreshing this page never triggers an investigation, a
// detection generation, or an AI call. Auto-refresh is capped well above the
// "no faster than 30-60s" floor.
const AUTO_REFRESH_MS = 60_000;

type State =
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | {
      kind: "ready";
      health: SystemHealthResponse;
      usage: UsageResponse;
      config: ConfigStatusResponse;
      fetchedAt: string;
    };

export default function DashboardPage() {
  const [state, setState] = useState<State>({ kind: "loading" });
  const [activeTab, setActiveTab] = useState("health");
  const abortRef = useRef<AbortController | null>(null);

  const load = useCallback(async () => {
    abortRef.current?.abort();
    const controller = new AbortController();
    abortRef.current = controller;
    try {
      const [health, usage, config] = await Promise.all([
        systemHealth(controller.signal),
        systemUsage(controller.signal),
        systemConfig(controller.signal),
      ]);
      setState({ kind: "ready", health, usage, config, fetchedAt: new Date().toISOString() });
    } catch (err) {
      if (err instanceof DOMException && err.name === "AbortError") return;
      setState({
        kind: "error",
        message: err instanceof Error ? err.message : "Could not reach the service.",
      });
    }
  }, []);

  useEffect(() => {
    load();
    const interval = setInterval(load, AUTO_REFRESH_MS);
    return () => {
      clearInterval(interval);
      abortRef.current?.abort();
    };
  }, [load]);

  return (
    <main className="min-h-screen px-4 py-10 sm:py-14">
      <div className="w-full max-w-5xl mx-auto space-y-6">
        <header className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <Link
              href="/"
              className="text-xs text-zinc-500 hover:text-zinc-300 transition-colors"
            >
              ← Back to Search
            </Link>
            <h1 className="text-2xl font-semibold text-white tracking-tight mt-1">
              Operational Dashboard
            </h1>
            <p className="text-zinc-500 text-sm mt-1">
              System health, API consumption, and configuration status. Read-only.
            </p>
          </div>
          <div className="flex items-center gap-3">
            {state.kind === "ready" && (
              <span className="text-xs text-zinc-600">
                Updated {formatTimestamp(state.fetchedAt)}
              </span>
            )}
            <button
              onClick={load}
              className="text-xs font-medium text-zinc-300 bg-zinc-800 hover:bg-zinc-700 border border-zinc-700 rounded-xl px-4 py-2 transition-colors"
            >
              Refresh
            </button>
          </div>
        </header>

        {state.kind === "loading" && (
          <div className="bg-zinc-900 border border-zinc-800 rounded-2xl p-8 text-center text-sm text-zinc-500">
            Loading operational status…
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
          <DashboardTabs
            idPrefix="dashboard"
            activeKey={activeTab}
            onChange={setActiveTab}
            tabs={[
              {
                key: "health",
                label: "System Health",
                content: <SystemHealthTab data={state.health} />,
              },
              {
                key: "usage",
                label: "API Consumption",
                content: <ApiConsumptionTab data={state.usage} />,
              },
              {
                key: "config",
                label: "Configuration",
                content: <ConfigurationTab data={state.config} />,
              },
            ]}
          />
        )}
      </div>
    </main>
  );
}
