import type { ReactNode } from "react";

import type {
  AggregatedResult,
  EntityType,
  InvestigationResponse,
  ReputationLevel,
  ResultStatus,
  ValidationStatus,
} from "@/lib/api";

// Human-readable labels for the engine's entity vocabulary.
const ENTITY_LABELS: Record<EntityType, string> = {
  ipv4: "IPv4 Address",
  ipv6: "IPv6 Address",
  domain: "Domain",
  url: "URL",
  email: "Email Address",
  md5: "MD5 Hash",
  sha1: "SHA-1 Hash",
  sha256: "SHA-256 Hash",
  cve: "CVE",
  mitre_technique: "MITRE ATT&CK Technique",
  registry_key: "Registry Key",
  process_name: "Process Name",
  powershell_command: "PowerShell Command",
  windows_api: "Windows API",
  file_name: "File Name",
  threat_actor: "Threat Actor",
  malware_family: "Malware Family",
  freetext: "Free Text",
  unknown: "Unknown",
};

const VALIDATION_STYLES: Record<ValidationStatus, string> = {
  valid: "text-emerald-400 border-emerald-500/30 bg-emerald-500/10",
  invalid: "text-red-400 border-red-500/30 bg-red-500/10",
  unvalidated: "text-zinc-400 border-zinc-600/40 bg-zinc-700/20",
};

const REPUTATION_STYLES: Record<ReputationLevel, string> = {
  unknown: "text-zinc-400 border-zinc-600/40 bg-zinc-700/20",
  benign: "text-emerald-400 border-emerald-500/30 bg-emerald-500/10",
  likely_benign: "text-emerald-400 border-emerald-500/30 bg-emerald-500/10",
  suspicious: "text-amber-400 border-amber-500/30 bg-amber-500/10",
  likely_malicious: "text-red-400 border-red-500/30 bg-red-500/10",
  malicious: "text-red-400 border-red-500/30 bg-red-500/10",
};

const STATUS_STYLES: Record<ResultStatus, string> = {
  ok: "text-emerald-400 border-emerald-500/30 bg-emerald-500/10",
  partial: "text-amber-400 border-amber-500/30 bg-amber-500/10",
  not_found: "text-zinc-400 border-zinc-600/40 bg-zinc-700/20",
  unsupported: "text-zinc-400 border-zinc-600/40 bg-zinc-700/20",
  error: "text-red-400 border-red-500/30 bg-red-500/10",
  timeout: "text-red-400 border-red-500/30 bg-red-500/10",
  rate_limited: "text-amber-400 border-amber-500/30 bg-amber-500/10",
  unauthorized: "text-amber-400 border-amber-500/30 bg-amber-500/10",
};

function labelFor(type: EntityType): string {
  return ENTITY_LABELS[type] ?? type;
}

function humanize(value: string): string {
  return value.replace(/_/g, " ");
}

export function SearchResult({ data }: { data: InvestigationResponse }) {
  const { entity, threat_intelligence, knowledge, investigation_id } = data;

  const hasTI = threat_intelligence.providers.length > 0;
  const hasKnowledge = knowledge.providers.length > 0;

  return (
    <div className="w-full space-y-4 text-left">
      {/* Entity Overview — always shown */}
      <section className="bg-zinc-900 border border-zinc-800 rounded-2xl p-5 space-y-5">
        <div className="flex items-center justify-between gap-3">
          <h2 className="text-sm font-semibold text-white">Entity Overview</h2>
          <span className="shrink-0 px-2.5 py-1 rounded-full bg-zinc-800 border border-zinc-700 text-xs text-zinc-300">
            {labelFor(entity.type)}
          </span>
        </div>

        <dl className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-4 text-sm">
          <ResultField label="Entity Type" value={labelFor(entity.type)} />
          <ResultField label="Validation Status">
            <span
              className={`inline-block px-2 py-0.5 rounded-md border text-xs font-medium capitalize ${VALIDATION_STYLES[entity.validation]}`}
            >
              {entity.validation}
            </span>
          </ResultField>
          <ResultField label="Normalized Value" full mono>
            {entity.normalized_value || "—"}
          </ResultField>
          <ResultField label="Confidence">
            <div className="flex items-center gap-2">
              <div className="h-1.5 w-24 rounded-full bg-zinc-800 overflow-hidden">
                <div
                  className="h-full bg-zinc-400"
                  style={{ width: `${entity.confidence}%` }}
                />
              </div>
              <span className="text-zinc-300 text-xs">{entity.confidence}%</span>
            </div>
          </ResultField>
        </dl>

        {entity.possible_matches.length > 0 && (
          <div>
            <p className="text-xs text-zinc-500 mb-2">Possible Matches</p>
            <div className="flex flex-wrap gap-2">
              {entity.possible_matches.map((match) => (
                <span
                  key={match.type}
                  className="px-2.5 py-1 rounded-lg bg-zinc-800/60 border border-zinc-700/60 text-xs text-zinc-300"
                >
                  {labelFor(match.type)} · {match.confidence}%
                </span>
              ))}
            </div>
          </div>
        )}

        <p className="text-[11px] text-zinc-600 font-mono break-all">
          Investigation ID: {investigation_id}
        </p>
      </section>

      {/* Threat Intelligence — hidden when no TI providers ran */}
      {hasTI && (
        <section className="bg-zinc-900 border border-zinc-800 rounded-2xl p-5 space-y-4">
          <h2 className="text-sm font-semibold text-white">Threat Intelligence</h2>
          <IntelligencePanel result={threat_intelligence} />
        </section>
      )}

      {/* Knowledge — hidden when no reference providers ran */}
      {hasKnowledge && (
        <section className="bg-zinc-900 border border-zinc-800 rounded-2xl p-5 space-y-4">
          <h2 className="text-sm font-semibold text-white">Knowledge</h2>
          <IntelligencePanel result={knowledge} />
        </section>
      )}

      {/* Neither framework has providers for this entity type */}
      {!hasTI && !hasKnowledge && (
        <section className="bg-zinc-900 border border-zinc-800 rounded-2xl p-5">
          <p className="text-xs text-zinc-500">
            No providers apply to this entity type yet.
          </p>
        </section>
      )}

      {/* AI Analysis — future phase placeholder */}
      <section className="bg-zinc-900/40 border border-dashed border-zinc-800/70 rounded-2xl p-5">
        <div className="flex items-center justify-between gap-3">
          <h2 className="text-sm font-medium text-zinc-500">AI Analysis</h2>
          <span className="shrink-0 text-[11px] text-zinc-600">
            Available in a future phase
          </span>
        </div>
      </section>
    </div>
  );
}

function IntelligencePanel({ result }: { result: AggregatedResult }) {
  const reputations = result.providers.filter((p) => p.reputation);
  const evidence = result.evidence.filter((e) => e.evidence.type !== "tag");
  const hasFindings =
    reputations.length > 0 ||
    evidence.length > 0 ||
    result.relationships.length > 0 ||
    result.references.length > 0 ||
    result.tags.length > 0;

  return (
    <div className="space-y-5">
      {/* Provider attribution */}
      <div className="flex flex-wrap gap-2">
        {result.providers.map((p) => (
          <span
            key={p.provider}
            className={`px-2.5 py-1 rounded-full border text-xs ${STATUS_STYLES[p.status]}`}
            title={p.error?.message ?? undefined}
          >
            {p.provider_display_name ?? p.provider} · {humanize(p.status)}
          </span>
        ))}
      </div>

      {reputations.length > 0 && (
        <div className="space-y-2">
          {reputations.map((p) => (
            <div key={p.provider} className="flex items-center gap-2 text-sm">
              <span
                className={`px-2 py-0.5 rounded-md border text-xs font-medium capitalize ${REPUTATION_STYLES[p.reputation!.level]}`}
              >
                {humanize(p.reputation!.level)}
              </span>
              <span className="text-zinc-400 text-xs">
                {p.reputation!.summary ?? p.provider_display_name ?? p.provider}
              </span>
            </div>
          ))}
        </div>
      )}

      {evidence.length > 0 && (
        <div>
          <p className="text-xs text-zinc-500 mb-2">Evidence</p>
          <ul className="space-y-1.5">
            {evidence.map((e, i) => (
              <li
                key={i}
                className="flex items-start justify-between gap-3 text-sm"
              >
                <span className="text-zinc-300">{e.evidence.summary}</span>
                <span className="shrink-0 text-[11px] text-zinc-600">
                  {e.sources.join(", ")}
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {result.relationships.length > 0 && (
        <div>
          <p className="text-xs text-zinc-500 mb-2">Related Entities</p>
          <div className="flex flex-wrap gap-2">
            {result.relationships.map((r) => (
              <span
                key={`${r.relationship.target_type}:${r.relationship.target_value}`}
                className="px-2.5 py-1 rounded-lg bg-zinc-800/60 border border-zinc-700/60 text-xs text-zinc-300"
              >
                {humanize(r.relationship.target_type)}: {r.relationship.target_value}
              </span>
            ))}
          </div>
        </div>
      )}

      {result.references.length > 0 && (
        <div>
          <p className="text-xs text-zinc-500 mb-2">References</p>
          <ul className="space-y-1">
            {result.references.map((r) => (
              <li key={r.reference.url}>
                <a
                  href={r.reference.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-xs text-blue-400 hover:text-blue-300 break-all"
                >
                  {r.reference.title}
                </a>
              </li>
            ))}
          </ul>
        </div>
      )}

      {result.tags.length > 0 && (
        <div>
          <p className="text-xs text-zinc-500 mb-2">Tags</p>
          <div className="flex flex-wrap gap-2">
            {result.tags.map((tag) => (
              <span
                key={tag}
                className="px-2.5 py-1 rounded-lg bg-zinc-800/60 border border-zinc-700/60 text-xs text-zinc-300"
              >
                {tag}
              </span>
            ))}
          </div>
        </div>
      )}

      {!hasFindings && (
        <p className="text-sm text-zinc-400">No intelligence found for this entity.</p>
      )}
    </div>
  );
}

function ResultField({
  label,
  value,
  children,
  mono,
  full,
}: {
  label: string;
  value?: string;
  children?: ReactNode;
  mono?: boolean;
  full?: boolean;
}) {
  return (
    <div className={full ? "sm:col-span-2" : undefined}>
      <dt className="text-xs text-zinc-500 mb-1">{label}</dt>
      <dd className={`text-zinc-200 ${mono ? "font-mono break-all" : ""}`}>
        {children ?? value}
      </dd>
    </div>
  );
}
