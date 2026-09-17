import type {
  AIUsage,
  DetectionEngineeringUsage,
  DetectionKnowledgeUsage,
  InvestigationUsage,
  KnowledgeProviderUsage,
  ProviderUsage,
  UsageResponse,
} from "@/lib/api";
import {
  formatBytes,
  formatLatency,
  formatNumber,
  formatPercent,
  formatTimestamp,
} from "@/lib/dashboard";

import { Badge, Field } from "../investigation/shared/DetectionDisclosure";

interface Props {
  data: UsageResponse;
}

export function ApiConsumptionTab({ data }: Props) {
  const reportedQuotas = data.threat_intelligence.filter(
    (provider) => provider.rate_limit !== null && provider.rate_limit_remaining !== null,
  );
  return (
    <div className="space-y-4">
      <section className="rounded-2xl border border-sky-500/20 bg-gradient-to-br from-sky-500/10 via-zinc-900 to-zinc-900 p-5">
        <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h2 className="text-sm font-semibold text-white">Live API usage</h2>
            <p className="mt-1 max-w-xl text-xs leading-relaxed text-zinc-500">
              Percentages use provider-reported quotas only. Success and cache bars are based on
              requests observed by this ThreatLens instance.
            </p>
          </div>
          <div className="flex items-center gap-3">
            <MetricRing
              label="Quotas reported"
              percent={percentage(reportedQuotas.length, data.threat_intelligence.length)}
              tone="sky"
              value={`${reportedQuotas.length}/${data.threat_intelligence.length}`}
            />
          </div>
        </div>
      </section>

      <Section title="Threat Intelligence" count={data.threat_intelligence.length}>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          {data.threat_intelligence.map((p) => (
            <ProviderCard key={p.name} provider={p} />
          ))}
        </div>
      </Section>

      <Section title="Knowledge Providers" count={data.knowledge.length}>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          {data.knowledge.map((p) => (
            <KnowledgeProviderCard key={p.name} provider={p} />
          ))}
        </div>
      </Section>

      <Section title="AI Provider">
        <AISection ai={data.ai} />
      </Section>

      <Section title="Detection Engineering">
        <DetectionEngineeringSection usage={data.detection_engineering} />
      </Section>

      <Section title="Detection Knowledge">
        <DetectionKnowledgeSection usage={data.detection_knowledge} />
      </Section>

      <Section title="Investigation Statistics">
        <InvestigationSection usage={data.investigations} />
      </Section>

      <Section title="Backup Reliability">
        <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
          {(data.backups ?? []).length === 0 && <p className="text-xs text-zinc-500">No backup activity in this server session.</p>}
          {(data.backups ?? []).map((item) => <div key={item.operation} className="rounded-xl border border-zinc-800 bg-zinc-950 p-3 text-xs"><p className="mb-2 capitalize text-zinc-200">{item.operation}</p><div className="grid grid-cols-2 gap-2"><Field label="Successful" value={String(item.successful)} /><Field label="Failed" value={String(item.failed)} /><Field label="Avg latency" value={formatLatency(item.avg_latency_ms)} /><Field label="Last run" value={formatTimestamp(item.last_request_at)} /></div></div>)}
        </div>
      </Section>
    </div>
  );
}

function Section({
  title,
  count,
  children,
}: {
  title: string;
  count?: number;
  children: React.ReactNode;
}) {
  return (
    <section className="bg-zinc-900 border border-zinc-800 rounded-2xl p-5">
      <h2 className="text-sm font-semibold text-white mb-4">
        {title}
        {count !== undefined && (
          <span className="ml-2 text-xs font-normal text-zinc-500">({count})</span>
        )}
      </h2>
      {children}
    </section>
  );
}

function ProviderCard({ provider }: { provider: ProviderUsage }) {
  const quotaUsed = quotaUsage(provider);
  const cacheRate = percentage(provider.cache_hits, provider.cache_hits + provider.cache_misses);
  return (
    <div className="bg-zinc-800/40 border border-zinc-700/50 rounded-xl p-4 space-y-3">
      <div className="flex items-center justify-between gap-2">
        <span className="text-sm font-medium text-zinc-200">{provider.display_name}</span>
        <Badge className={provider.configured ? "border-emerald-500/30 text-emerald-400" : "border-zinc-600/40 text-zinc-500"}>
          {provider.configured ? "Configured" : "Not configured"}
        </Badge>
      </div>
      <div className="grid gap-4 border-y border-zinc-700/50 py-3 sm:grid-cols-[auto_1fr] sm:items-center">
        <MetricRing
          label="Quota used"
          percent={quotaUsed}
          tone={quotaTone(quotaUsed)}
          value={quotaUsed === null ? "—" : `${Math.round(quotaUsed)}%`}
        />
        <div className="space-y-3">
          <ProgressMetric label="Successful requests" percent={provider.success_rate} />
          <ProgressMetric label="Cache efficiency" percent={cacheRate} tone="sky" />
        </div>
      </div>
      <div className="grid grid-cols-2 sm:grid-cols-3 gap-2.5 text-xs">
        <Field label="Requests" value={String(provider.requests)} />
        <Field label="Successful" value={String(provider.successful)} />
        <Field label="Failed" value={String(provider.failed)} />
        <Field label="Success Rate" value={formatPercent(provider.success_rate)} />
        <Field label="Avg Latency" value={formatLatency(provider.avg_latency_ms)} />
        <Field label="Last Request" value={formatTimestamp(provider.last_request_at)} />
        <Field
          label="Rate Limit Remaining"
          value={provider.rate_limit_remaining === null ? "Not reported" : String(provider.rate_limit_remaining)}
        />
        <Field label="Cache Hits" value={String(provider.cache_hits)} />
        <Field label="Cache Misses" value={String(provider.cache_misses)} />
      </div>
    </div>
  );
}

function KnowledgeProviderCard({ provider }: { provider: KnowledgeProviderUsage }) {
  const successRate = percentage(provider.successful, provider.successful + provider.failed);
  const cacheRate = percentage(provider.cache_hits, provider.cache_hits + provider.cache_misses);
  return (
    <div className="bg-zinc-800/40 border border-zinc-700/50 rounded-xl p-4 space-y-3">
      <span className="text-sm font-medium text-zinc-200">{provider.display_name}</span>
      <div className="space-y-3 border-y border-zinc-700/50 py-3">
        <ProgressMetric label="Successful queries" percent={successRate} />
        <ProgressMetric label="Cache efficiency" percent={cacheRate} tone="sky" />
      </div>
      <div className="grid grid-cols-2 sm:grid-cols-3 gap-2.5 text-xs">
        <Field label="Queries" value={String(provider.queries)} />
        <Field label="Success" value={String(provider.successful)} />
        <Field label="Failure" value={String(provider.failed)} />
        <Field label="Avg Latency" value={formatLatency(provider.avg_latency_ms)} />
        <Field label="Cache Hits" value={String(provider.cache_hits)} />
        <Field label="Cache Misses" value={String(provider.cache_misses)} />
      </div>
    </div>
  );
}

function AISection({ ai }: { ai: AIUsage }) {
  const successRate = percentage(ai.successful, ai.successful + ai.failed);
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <Badge className="border-zinc-600/40 text-zinc-300">{ai.provider}</Badge>
        {ai.model && <Badge className="border-zinc-600/40 text-zinc-300">{ai.model}</Badge>}
        <Badge className={ai.enabled ? "border-emerald-500/30 text-emerald-400" : "border-zinc-600/40 text-zinc-500"}>
          {ai.enabled ? "Enabled" : "Disabled"}
        </Badge>
        <Badge className={ai.connected ? "border-emerald-500/30 text-emerald-400" : "border-zinc-600/40 text-zinc-500"}>
          {ai.connected ? "Connected" : "Not Connected"}
        </Badge>
      </div>
      <ProgressMetric label="Successful AI responses" percent={successRate} />
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 text-xs">
        <Field label="Requests" value={String(ai.requests)} />
        <Field label="Successful" value={String(ai.successful)} />
        <Field label="Failed" value={String(ai.failed)} />
        <Field label="Avg Response" value={formatLatency(ai.avg_response_ms)} />
        <Field label="Fastest Response" value={formatLatency(ai.fastest_response_ms)} />
        <Field label="Slowest Response" value={formatLatency(ai.slowest_response_ms)} />
        <Field label="Avg Prompt Size" value={formatNumber(ai.avg_prompt_chars)} />
        <Field label="Avg Completion Size" value={formatNumber(ai.avg_completion_chars)} />
        {ai.estimated_tokens !== null && (
          <Field label="Estimated Tokens" value={formatNumber(ai.estimated_tokens)} />
        )}
        {ai.estimated_cost_usd !== null && (
          <Field label="Estimated Cost" value={`$${formatNumber(ai.estimated_cost_usd, 4)}`} />
        )}
      </div>
    </div>
  );
}

function DetectionEngineeringSection({ usage }: { usage: DetectionEngineeringUsage }) {
  const languages = Object.entries(usage.by_language);
  return (
    <div className="space-y-3">
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 text-xs">
        <Field label="Generated Total" value={String(usage.generated_total)} />
        <Field label="Avg Generation Time" value={formatLatency(usage.avg_generation_ms)} />
        <Field label="Last Generation" value={formatTimestamp(usage.last_generated_at)} />
      </div>
      {languages.length > 0 && (
        <div>
          <p className="text-[11px] text-zinc-500 mb-2">By Language</p>
          <div className="flex flex-wrap gap-1.5">
            {languages.map(([language, count]) => (
              <Badge key={language} className="border-zinc-600/40 text-zinc-300">
                {language}: {count}
              </Badge>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function DetectionKnowledgeSection({ usage }: { usage: DetectionKnowledgeUsage }) {
  return (
    <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 text-xs">
      <Field label="Library Version" value={usage.library_version} />
      <Field label="Rules Indexed" value={String(usage.rules_indexed)} />
      <Field label="Repositories" value={String(usage.repositories)} />
      <Field label="Sync Status" value={usage.sync_status} />
      <Field label="Last Synchronized" value={formatTimestamp(usage.last_synchronized_at)} />
      <Field label="Cache Size" value={formatBytes(usage.cache_size_bytes)} />
      <Field label="Queries" value={String(usage.queries)} />
      <Field label="Avg Query Latency" value={formatLatency(usage.avg_query_latency_ms)} />
    </div>
  );
}

function InvestigationSection({ usage }: { usage: InvestigationUsage }) {
  return (
    <div className="grid grid-cols-2 sm:grid-cols-3 gap-2.5 text-xs">
      <Field label="Investigations Executed" value={String(usage.executed)} />
      <Field label="Avg Duration" value={formatLatency(usage.avg_duration_ms)} />
      <Field label="Avg Findings" value={formatNumber(usage.avg_findings)} />
      <Field label="Avg Recommendations" value={formatNumber(usage.avg_recommendations)} />
      <Field label="Avg Confidence" value={formatNumber(usage.avg_confidence)} />
      <Field label="Avg AI Response" value={formatLatency(usage.avg_ai_response_ms)} />
    </div>
  );
}

type MetricTone = "emerald" | "amber" | "red" | "sky" | "zinc";

const toneClasses: Record<MetricTone, { text: string; bar: string }> = {
  emerald: { text: "text-emerald-400", bar: "bg-emerald-400" },
  amber: { text: "text-amber-400", bar: "bg-amber-400" },
  red: { text: "text-red-400", bar: "bg-red-400" },
  sky: { text: "text-sky-400", bar: "bg-sky-400" },
  zinc: { text: "text-zinc-500", bar: "bg-zinc-600" },
};

function percentage(value: number, total: number): number | null {
  if (total <= 0) return null;
  return Math.min(100, Math.max(0, (value / total) * 100));
}

function quotaUsage(provider: ProviderUsage): number | null {
  if (
    provider.rate_limit === null
    || provider.rate_limit <= 0
    || provider.rate_limit_remaining === null
  ) return null;
  return percentage(provider.rate_limit - provider.rate_limit_remaining, provider.rate_limit);
}

function quotaTone(percent: number | null): MetricTone {
  if (percent === null) return "zinc";
  if (percent >= 90) return "red";
  if (percent >= 70) return "amber";
  return "emerald";
}

function MetricRing({
  label,
  percent,
  value,
  tone,
}: {
  label: string;
  percent: number | null;
  value: string;
  tone: MetricTone;
}) {
  const radius = 25;
  const circumference = 2 * Math.PI * radius;
  const progress = percent ?? 0;
  const color = toneClasses[tone].text;
  return (
    <div
      className="flex min-w-36 items-center gap-3"
      title={percent === null ? `${label}: not reported` : `${label}: ${percent.toFixed(1)}%`}
    >
      <div className="relative h-16 w-16 shrink-0">
        <svg className="h-16 w-16 -rotate-90" viewBox="0 0 64 64" aria-hidden="true">
          <circle cx="32" cy="32" r={radius} fill="none" stroke="currentColor" strokeWidth="6" className="text-zinc-800" />
          <circle
            cx="32"
            cy="32"
            r={radius}
            fill="none"
            stroke="currentColor"
            strokeWidth="6"
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={circumference * (1 - progress / 100)}
            className={`${color} transition-[stroke-dashoffset] duration-700 ease-out`}
          />
        </svg>
        <span className={`absolute inset-0 flex items-center justify-center text-xs font-semibold ${color}`}>
          {value}
        </span>
      </div>
      <div>
        <p className="text-xs font-medium text-zinc-300">{label}</p>
        <p className="mt-0.5 text-[10px] text-zinc-600">
          {percent === null ? "Not reported" : "Current window"}
        </p>
      </div>
    </div>
  );
}

function ProgressMetric({
  label,
  percent,
  tone = "emerald",
}: {
  label: string;
  percent: number | null;
  tone?: MetricTone;
}) {
  const normalized = percent === null ? 0 : Math.min(100, Math.max(0, percent));
  const colors = toneClasses[percent === null ? "zinc" : tone];
  return (
    <div>
      <div className="mb-1.5 flex items-center justify-between gap-3 text-[11px]">
        <span className="text-zinc-500">{label}</span>
        <span className={`font-medium tabular-nums ${colors.text}`}>
          {percent === null ? "No data" : `${percent.toFixed(1)}%`}
        </span>
      </div>
      <div
        className="h-2 overflow-hidden rounded-full bg-zinc-800"
        role="progressbar"
        aria-label={label}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={percent === null ? undefined : Math.round(normalized)}
        aria-valuetext={percent === null ? "No data" : `${percent.toFixed(1)} percent`}
      >
        <div
          className={`h-full rounded-full ${colors.bar} transition-[width] duration-700 ease-out`}
          style={{ width: `${normalized}%` }}
        />
      </div>
    </div>
  );
}
