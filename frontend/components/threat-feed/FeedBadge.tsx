import type { ReactNode } from "react";

type Tone = "neutral" | "info" | "critical" | "high" | "medium" | "low";
const tones: Record<Tone, string> = {
  neutral: "border-zinc-700 bg-zinc-800/70 text-zinc-300",
  info: "border-sky-700/50 bg-sky-500/10 text-sky-300",
  critical: "border-red-500/40 bg-red-500/10 text-red-300",
  high: "border-amber-500/40 bg-amber-500/10 text-amber-300",
  medium: "border-sky-500/30 bg-sky-500/10 text-sky-300",
  low: "border-emerald-500/30 bg-emerald-500/10 text-emerald-300",
};
export function FeedBadge({ children, tone = "neutral" }: { children?: ReactNode; tone?: Tone }) {
  return <span className={`feed-badge inline-flex rounded-full border px-2 py-0.5 text-[11px] font-medium leading-4 ${tones[tone]}`}>{children}</span>;
}
export function FeedSeverityBadge({ severity }: { severity: string | null }) {
  const normalized = severity?.toLowerCase();
  const tone: Tone = normalized === "critical" || normalized === "high" || normalized === "medium" || normalized === "low" ? normalized : "neutral";
  return <FeedBadge tone={tone}>{normalized || "Not rated"}</FeedBadge>;
}
