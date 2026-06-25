import type { ReactNode } from "react";

import type {
  EntityType,
  IntelligenceResponse,
  IntelligenceResult,
  ReputationLevel,
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

function labelFor(type: EntityType): string {
  return ENTITY_LABELS[type] ?? type;
}

function metaStr(meta: Record<string, unknown>, key: string): string | null {
  const value = meta[key];
  return typeof value === "string" && value ? value : null;
}

export function SearchResult({ data }: { data: IntelligenceResponse }) {
  const { entity, results, search_id } = data;
  const malwareBazaar = results.find((r) => r.provider === "malwarebazaar");

  return (
    <div className="w-full space-y-4 text-left">
      {/* Entity Information (live) */}
      <section className="bg-zinc-900 border border-zinc-800 rounded-2xl p-5 space-y-5">
        <div className="flex items-center justify-between gap-3">
          <h2 className="text-sm font-semibold text-white">Entity Information</h2>
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
          Search ID: {search_id}
        </p>
      </section>

      {/* Threat Intelligence — MalwareBazaar when applicable, else a placeholder. */}
      <section className="bg-zinc-900 border border-zinc-800 rounded-2xl p-5 space-y-4">
        <h2 className="text-sm font-semibold text-white">Threat Intelligence</h2>
        {malwareBazaar ? (
          <MalwareBazaarCard result={malwareBazaar} />
        ) : (
          <p className="text-xs text-zinc-600">
            No intelligence providers apply to this entity type yet.
          </p>
        )}
      </section>

      {/* Future-phase placeholders (structural only). */}
      {["AI Analysis", "Related Intelligence"].map((title) => (
        <section
          key={title}
          className="bg-zinc-900/40 border border-dashed border-zinc-800/70 rounded-2xl p-5"
        >
          <div className="flex items-center justify-between gap-3">
            <h2 className="text-sm font-medium text-zinc-500">{title}</h2>
            <span className="shrink-0 text-[11px] text-zinc-600">
              Available in a future phase
            </span>
          </div>
        </section>
      ))}
    </div>
  );
}

function MalwareBazaarCard({ result }: { result: IntelligenceResult }) {
  const name = result.provider_display_name ?? "MalwareBazaar";

  if (result.status !== "ok") {
    return (
      <div className="space-y-1">
        <p className="text-xs text-zinc-500">{name}</p>
        <p className="text-sm text-zinc-400">{malwareBazaarStatusMessage(result)}</p>
      </div>
    );
  }

  const family = metaStr(result.metadata, "signature");
  const fileType = metaStr(result.metadata, "file_type");
  const firstSeen = metaStr(result.metadata, "first_seen");
  const sampleAvailable = result.metadata.sample_available === true;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-3">
        <span className="text-xs text-zinc-500">{name}</span>
        {result.reputation && (
          <span
            className={`px-2 py-0.5 rounded-md border text-xs font-medium capitalize ${REPUTATION_STYLES[result.reputation.level]}`}
          >
            {result.reputation.level.replace(/_/g, " ")}
          </span>
        )}
      </div>

      <dl className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-4 text-sm">
        <ResultField label="Malware Family" value={family ?? "—"} />
        <ResultField label="File Type" value={fileType ?? "—"} />
        <ResultField label="Signature" value={family ?? "—"} />
        <ResultField label="First Seen" value={firstSeen ?? "—"} />
        <ResultField
          label="Sample Status"
          value={sampleAvailable ? "Available in MalwareBazaar" : "Not available"}
        />
      </dl>

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

      {result.references.length > 0 && (
        <div>
          <p className="text-xs text-zinc-500 mb-2">References</p>
          <ul className="space-y-1">
            {result.references.map((ref) => (
              <li key={ref.url}>
                <a
                  href={ref.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-xs text-blue-400 hover:text-blue-300 break-all"
                >
                  {ref.title}
                </a>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

function malwareBazaarStatusMessage(result: IntelligenceResult): string {
  switch (result.status) {
    case "not_found":
      return "No MalwareBazaar results found.";
    case "unauthorized":
      return "MalwareBazaar requires an API key. Set MALWAREBAZAAR_AUTH_KEY (free at auth.abuse.ch).";
    case "rate_limited":
      return "MalwareBazaar rate limit reached — try again shortly.";
    default:
      return "MalwareBazaar is temporarily unavailable.";
  }
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
