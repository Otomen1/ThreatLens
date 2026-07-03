// Pure presentation utilities for the Operational Dashboard.
// No JSX — safe to import from both server and client components.

import type { ServiceState } from "./api";

/** Tailwind classes for a status badge, matching the app's existing badge language. */
export function statusBadgeClasses(status: ServiceState): string {
  switch (status) {
    case "healthy":
      return "text-emerald-400 bg-emerald-500/10 border-emerald-500/30";
    case "degraded":
      return "text-amber-400 bg-amber-500/10 border-amber-500/30";
    case "offline":
      return "text-red-400 bg-red-500/10 border-red-500/30";
    default: // disabled
      return "text-zinc-400 bg-zinc-700/20 border-zinc-600/40";
  }
}

export function statusDotClass(status: ServiceState): string {
  switch (status) {
    case "healthy":
      return "bg-emerald-400";
    case "degraded":
      return "bg-amber-400";
    case "offline":
      return "bg-red-400";
    default: // disabled
      return "bg-zinc-500";
  }
}

export function statusLabel(status: ServiceState): string {
  const labels: Record<ServiceState, string> = {
    healthy: "Healthy",
    degraded: "Degraded",
    offline: "Offline",
    disabled: "Disabled",
  };
  return labels[status] ?? status;
}

/** "142 ms" / "1.2 s" / "—" for null. */
export function formatLatency(ms: number | null): string {
  if (ms === null || ms === undefined) return "—";
  if (ms >= 1000) return `${(ms / 1000).toFixed(1)} s`;
  return `${Math.round(ms)} ms`;
}

/** "98.5%" / "—" for null. */
export function formatPercent(rate: number | null): string {
  if (rate === null || rate === undefined) return "—";
  return `${rate.toFixed(1)}%`;
}

/** "1.2 KB" / "3.4 MB" / "—" for null/0. */
export function formatBytes(bytes: number | null): string {
  if (bytes === null || bytes === undefined) return "—";
  if (bytes === 0) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  const exponent = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  const value = bytes / Math.pow(1024, exponent);
  return `${exponent === 0 ? value : value.toFixed(1)} ${units[exponent]}`;
}

/** A locale-formatted timestamp, or "—" for null/missing. */
export function formatTimestamp(iso: string | null): string {
  if (!iso) return "—";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return "—";
  return date.toLocaleString("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });
}

/** "82.30" trimmed to at most 2 decimals, or "—" for null. */
export function formatNumber(value: number | null, decimals = 1): string {
  if (value === null || value === undefined) return "—";
  return value.toFixed(decimals).replace(/\.0+$/, "");
}
