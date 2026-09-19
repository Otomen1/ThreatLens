import type { AIConfigStatus, ConfigItem, ConfigStatusResponse, ProviderUsage } from "@/lib/api";

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
  providers?: ProviderUsage[];
}

export function ConfigurationTab({ data, providers = [] }: Props) {
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
        <div className="px-5 pt-5 pb-3">
          <h2 className="text-sm font-semibold text-white">Identity Intelligence</h2>
          <p className="mt-1 text-xs text-zinc-500">
            Email exposure uses HIBP when enabled and configured. Password checks never store or
            transmit plaintext passwords.
          </p>
        </div>
        {(data.identity ?? []).map((item) => <ConfigRow key={item.name} item={item} />)}
      </section>

      <section className="overflow-hidden rounded-2xl border border-zinc-800 bg-zinc-900"><div className="px-5 pb-3 pt-5"><h2 className="text-sm font-semibold text-white">Passive provider diagnostics</h2><p className="mt-1 text-xs text-zinc-500">Based only on observed requests; no quota-consuming probes are performed.</p></div>{providers.map((provider) => <div key={provider.name} className="border-t border-zinc-800 px-4 py-3 text-xs"><div className="flex items-center justify-between"><span className="text-zinc-200">{provider.display_name}</span><span className={provider.last_safe_error_code ? "text-amber-300" : "text-emerald-300"}>{provider.last_safe_error_code ?? (provider.configured ? "healthy / not yet observed" : "not configured")}</span></div><div className="mt-2 flex flex-wrap gap-3 text-zinc-500"><span>Requests {provider.requests}</span><span>Rate limited {provider.rate_limited_count}</span><span>Quota {provider.rate_limit_remaining === null ? "Not reported" : `${provider.rate_limit_remaining}/${provider.rate_limit ?? "?"}`}</span>{provider.rate_limit_reset_at && <span>Reset {provider.rate_limit_reset_at}</span>}</div>{provider.suggested_action && <p className="mt-2 text-amber-200">{provider.suggested_action}</p>}</div>)}</section>

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
