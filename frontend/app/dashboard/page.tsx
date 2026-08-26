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
          <>
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-3" aria-label="Operational summary">
            <Kpi label="Investigations" value={state.usage.investigations.executed} detail={`${state.usage.investigations.avg_duration_ms ?? "—"} ms avg`} />
            <Kpi label="Avg findings" value={state.usage.investigations.avg_findings ?? "—"} detail={`${state.usage.investigations.avg_confidence ?? "—"} confidence`} />
            <Kpi label="Detection rules" value={state.usage.detection_engineering.generated_total} detail={`${state.usage.detection_engineering.avg_generation_ms ?? "—"} ms avg`} />
            <Kpi label="Configured sources" value={state.config.threat_intelligence.filter((item) => item.configured).length} detail={`${state.config.threat_intelligence.length} total providers`} />
          </div>
          <div className="grid gap-3 lg:grid-cols-3">
            <ServiceOverview services={state.health.services} />
            <DetectionOverview data={state.usage.detection_engineering} />
            <QuickLinks />
          </div>
          {(() => {
            const warnings = state.health.services.filter((service) => service.status === "degraded" || service.status === "offline");
            return warnings.length > 0 ? <div className="rounded-xl border border-amber-500/20 bg-amber-500/5 px-4 py-3 text-xs text-amber-300/90" role="status"><span className="font-semibold">Attention needed:</span> {warnings.map((warning) => `${warning.display_name} (${warning.status})`).join(" · ")}</div> : null;
          })()}
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
          </>
        )}
      </div>
    </main>
  );
}

function Kpi({ label, value, detail }: { label: string; value: string | number; detail: string }) {
  return <div className="bg-zinc-900 border border-zinc-800 rounded-2xl p-4"><p className="text-[10px] uppercase tracking-wider text-zinc-600">{label}</p><p className="text-2xl font-semibold text-white mt-2">{value}</p><p className="text-[11px] text-zinc-500 mt-1">{detail}</p></div>;
}

function ServiceOverview({ services }: { services: SystemHealthResponse["services"] }) {
  return <section className="rounded-2xl border border-zinc-800 bg-zinc-900 p-4"><div className="flex items-center justify-between"><h2 className="text-sm font-semibold text-zinc-200">Service health</h2><span className="text-[11px] text-zinc-500">{services.filter((item) => item.status === "healthy").length}/{services.length} healthy</span></div><div className="mt-3 space-y-2">{services.slice(0, 4).map((service) => <div key={service.name} className="flex items-center justify-between gap-2 text-xs"><span className="truncate text-zinc-400">{service.display_name}</span><span className={`rounded-full px-2 py-0.5 text-[10px] ${service.status === "healthy" ? "bg-emerald-500/10 text-emerald-300" : service.status === "disabled" ? "bg-zinc-800 text-zinc-500" : "bg-amber-500/10 text-amber-300"}`}>{service.status}</span></div>)}</div></section>;
}

function DetectionOverview({ data }: { data: UsageResponse["detection_engineering"] }) {
  const formats = Object.entries(data.by_language).sort(([, a], [, b]) => b - a).slice(0, 4);
  return <section className="rounded-2xl border border-zinc-800 bg-zinc-900 p-4"><div className="flex items-center justify-between"><h2 className="text-sm font-semibold text-zinc-200">Detection output</h2><Link href="/detections" className="text-[11px] text-sky-400 hover:underline">Open workspace</Link></div>{formats.length ? <div className="mt-3 space-y-2">{formats.map(([language, count]) => <div key={language} className="flex items-center justify-between text-xs"><span className="font-mono text-zinc-400">{language}</span><span className="text-zinc-200">{count}</span></div>)}</div> : <p className="mt-3 text-xs text-zinc-500">No detections generated yet.</p>}</section>;
}

function QuickLinks() {
  return <section className="rounded-2xl border border-zinc-800 bg-zinc-900 p-4"><h2 className="text-sm font-semibold text-zinc-200">Quick access</h2><div className="mt-3 grid gap-2"><Link href="/workspace" className="rounded-lg border border-zinc-800 bg-zinc-950/40 px-3 py-2 text-xs text-zinc-400 hover:border-zinc-700 hover:text-zinc-200">Investigation Workspace <span className="float-right">→</span></Link><Link href="/detections" className="rounded-lg border border-zinc-800 bg-zinc-950/40 px-3 py-2 text-xs text-zinc-400 hover:border-zinc-700 hover:text-zinc-200">Detection Workspace <span className="float-right">→</span></Link></div></section>;
}
