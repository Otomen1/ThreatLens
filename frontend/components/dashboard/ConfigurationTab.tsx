import type { AIConfigStatus, ConfigItem, ConfigStatusResponse } from "@/lib/api";

function ConfiguredBadge({ configured }: { configured: boolean }) {
  return (
    <span
      className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-md border text-[11px] font-semibold uppercase tracking-wide ${
        configured
          ? "text-emerald-400 bg-emerald-500/10 border-emerald-500/30"
          : "text-zinc-400 bg-zinc-700/20 border-zinc-600/40"
      }`}
    >
      {configured ? "Configured ✓" : "Not Configured"}
    </span>
  );
}

function ConfigRow({ item }: { item: ConfigItem }) {
  return (
    <div className="flex items-center justify-between gap-3 px-4 py-3 border-b border-zinc-800 last:border-b-0">
      <div className="min-w-0">
        <span className="text-sm text-zinc-200">{item.display_name}</span>
        {!item.enabled && <span className="ml-2 text-[11px] text-zinc-600">Disabled</span>}
      </div>
      <ConfiguredBadge configured={item.configured} />
    </div>
  );
}

interface Props {
  data: ConfigStatusResponse;
}

export function ConfigurationTab({ data }: Props) {
  return (
    <div className="space-y-4">
      <section className="bg-zinc-900 border border-zinc-800 rounded-2xl overflow-hidden">
        <h2 className="text-sm font-semibold text-white px-5 pt-5 pb-3">
          Threat Intelligence
          <span className="ml-2 text-xs font-normal text-zinc-500">
            ({data.threat_intelligence.length})
          </span>
        </h2>
        <div>
          {data.threat_intelligence.map((item) => (
            <ConfigRow key={item.name} item={item} />
          ))}
        </div>
      </section>

      <section className="bg-zinc-900 border border-zinc-800 rounded-2xl overflow-hidden">
        <h2 className="text-sm font-semibold text-white px-5 pt-5 pb-3">
          Knowledge
          <span className="ml-2 text-xs font-normal text-zinc-500">({data.knowledge.length})</span>
        </h2>
        <div>
          {data.knowledge.map((item) => (
            <ConfigRow key={item.name} item={item} />
          ))}
        </div>
      </section>

      <section className="bg-zinc-900 border border-zinc-800 rounded-2xl p-5">
        <h2 className="text-sm font-semibold text-white mb-3">AI Provider</h2>
        <AIConfigRow ai={data.ai} />
      </section>
    </div>
  );
}

function AIConfigRow({ ai }: { ai: AIConfigStatus }) {
  return (
    <div className="flex items-center justify-between gap-3">
      <div className="flex items-center gap-3">
        <span className="text-sm text-zinc-200 capitalize">{ai.provider}</span>
        {ai.model && <span className="text-xs font-mono text-zinc-500">{ai.model}</span>}
      </div>
      <span
        className={`inline-flex items-center px-2 py-0.5 rounded-md border text-[11px] font-semibold uppercase tracking-wide ${
          ai.enabled
            ? "text-emerald-400 bg-emerald-500/10 border-emerald-500/30"
            : "text-zinc-400 bg-zinc-700/20 border-zinc-600/40"
        }`}
      >
        {ai.enabled ? "Enabled" : "Disabled"}
      </span>
    </div>
  );
}
