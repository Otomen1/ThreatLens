import type { AggregatedResult, AttributedEvidence, Entity, ProviderSummary } from "@/lib/api";
import {
  entityLabel,
  isIocType,
  reputationClasses,
  reputationLabel,
  worstReputation,
} from "@/lib/investigation";

interface Props {
  entity: Entity;
  threatIntelligence: AggregatedResult;
  knowledge: AggregatedResult;
  relationshipCount: number;
  referenceCount: number;
  timestamp: string;
}

/**
 * A compact investigation summary: identity, reputation/classification, scope
 * counts (sources queried, relationships, references), confidence/validation,
 * and the investigation timestamp. Every value already exists elsewhere in the
 * response (the header, the Relationships/References sections) — this card
 * only reorganizes it into one scannable place.
 */
export function OverviewCard({
  entity,
  threatIntelligence,
  knowledge,
  relationshipCount,
  referenceCount,
  timestamp,
}: Props) {
  const tiOk = threatIntelligence.providers.filter(
    (p) => p.status === "ok" || p.status === "partial",
  ).length;
  const kbOk = knowledge.providers.filter(
    (p) => p.status === "ok" || p.status === "partial",
  ).length;

  return (
    <div className="bg-zinc-900 border border-zinc-800 rounded-2xl p-5 flex flex-col gap-4">
      <h2 className="text-[11px] font-medium text-zinc-500 uppercase tracking-wider">
        Overview
      </h2>

      {/* Identity */}
      <div className="space-y-3">
        <Field label="Entity">
          <span className="font-mono text-xs break-all">{entity.value}</span>
        </Field>
        <Field label="Entity Type">{entityLabel(entity.type)}</Field>
      </div>

      {/* Reputation / classification */}
      <div className="pt-3 border-t border-zinc-800">
        {isIocType(entity.type) ? (
          <IocReputation providers={threatIntelligence.providers} />
        ) : (
          <ReferenceClassification evidence={knowledge.evidence} />
        )}
      </div>

      {/* Scope counts — same figures shown in the header, kept in sync */}
      <dl className="grid grid-cols-2 gap-3 pt-3 border-t border-zinc-800">
        <CountField label="Sources Queried" value={tiOk} />
        <CountField label="Knowledge Sources" value={kbOk} />
        <CountField label="Relationships" value={relationshipCount} />
        <CountField label="References" value={referenceCount} />
      </dl>

      {/* Confidence / validation */}
      <div className="pt-3 border-t border-zinc-800 space-y-3">
        <Field label="Confidence">
          <div className="flex items-center gap-2">
            <div className="h-1.5 w-20 rounded-full bg-zinc-800 overflow-hidden flex-shrink-0">
              <div
                className="h-full bg-zinc-400 transition-all"
                style={{ width: `${entity.confidence}%` }}
              />
            </div>
            <span className="text-zinc-300 text-xs">{entity.confidence}%</span>
          </div>
        </Field>

        <Field label="Validation">
          <ValidationBadge status={entity.validation} />
        </Field>

        {entity.possible_matches.length > 0 && (
          <Field label="Alt. Types">
            <div className="flex flex-wrap gap-1 mt-0.5">
              {entity.possible_matches.slice(0, 3).map((m) => (
                <span
                  key={m.type}
                  className="px-1.5 py-0.5 rounded bg-zinc-800 border border-zinc-700 text-[10px] text-zinc-500"
                >
                  {entityLabel(m.type)} {m.confidence}%
                </span>
              ))}
            </div>
          </Field>
        )}
      </div>

      {/* Timestamp */}
      <div className="pt-3 border-t border-zinc-800">
        <Field label="Investigation Timestamp">
          <span className="font-mono text-xs text-zinc-400">{timestamp}</span>
        </Field>
      </div>
    </div>
  );
}

function IocReputation({ providers }: { providers: ProviderSummary[] }) {
  const worst = worstReputation(providers);

  return (
    <div>
      <p className="text-[11px] text-zinc-500 mb-2">Reputation</p>
      {worst ? (
        <span
          className={`inline-block px-3 py-1.5 rounded-lg border text-sm font-bold uppercase tracking-wider ${reputationClasses(worst)}`}
        >
          {reputationLabel(worst)}
        </span>
      ) : (
        <span className="text-zinc-500 text-sm">No data</span>
      )}
    </div>
  );
}

function ReferenceClassification({ evidence }: { evidence: AttributedEvidence[] }) {
  const classification = evidence.find((e) => e.evidence.type === "classification");
  const categories = evidence.filter((e) => e.evidence.type === "category");

  return (
    <div className="space-y-3">
      {classification ? (
        <div>
          <p className="text-[11px] text-zinc-500 mb-1.5">Classification</p>
          <p className="text-sm text-zinc-200 leading-snug">{classification.evidence.summary}</p>
        </div>
      ) : (
        <p className="text-sm text-zinc-500">No classification available</p>
      )}

      {categories.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {categories.map((c, i) => (
            <span
              key={i}
              className="px-2 py-0.5 rounded-md bg-zinc-800 border border-zinc-700 text-xs text-zinc-400"
            >
              {c.evidence.value ?? c.evidence.summary.replace(/^[^:]+:\s*/, "")}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

function ValidationBadge({ status }: { status: string }) {
  const cls =
    status === "valid"
      ? "text-emerald-400 border-emerald-500/30 bg-emerald-500/10"
      : status === "invalid"
        ? "text-red-400 border-red-500/30 bg-red-500/10"
        : "text-zinc-400 border-zinc-600/40 bg-zinc-700/20";
  return (
    <span className={`inline-block px-2 py-0.5 rounded-md border text-xs font-medium capitalize ${cls}`}>
      {status}
    </span>
  );
}

function Field({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div>
      <dt className="text-[11px] text-zinc-500 mb-1">{label}</dt>
      <dd className="text-sm text-zinc-300">{children}</dd>
    </div>
  );
}

function CountField({ label, value }: { label: string; value: number }) {
  return (
    <div>
      <dt className="text-[11px] text-zinc-500 mb-1">{label}</dt>
      <dd className="text-sm font-semibold text-white">{value}</dd>
    </div>
  );
}
