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
  return (
    <div className="space-y-4">
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
  return (
    <div className="bg-zinc-800/40 border border-zinc-700/50 rounded-xl p-4 space-y-3">
      <div className="flex items-center justify-between gap-2">
        <span className="text-sm font-medium text-zinc-200">{provider.display_name}</span>
        <Badge className={provider.configured ? "border-emerald-500/30 text-emerald-400" : "border-zinc-600/40 text-zinc-500"}>
          {provider.configured ? "Configured" : "Not configured"}
        </Badge>
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
          value={provider.rate_limit_remaining === null ? "—" : String(provider.rate_limit_remaining)}
        />
        <Field label="Cache Hits" value={String(provider.cache_hits)} />
        <Field label="Cache Misses" value={String(provider.cache_misses)} />
      </div>
    </div>
  );
}

function KnowledgeProviderCard({ provider }: { provider: KnowledgeProviderUsage }) {
  return (
    <div className="bg-zinc-800/40 border border-zinc-700/50 rounded-xl p-4 space-y-3">
      <span className="text-sm font-medium text-zinc-200">{provider.display_name}</span>
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
