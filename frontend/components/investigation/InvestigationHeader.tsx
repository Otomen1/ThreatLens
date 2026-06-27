import type { AggregatedResult, Entity } from "@/lib/api";
import { entityLabel } from "@/lib/investigation";

interface Props {
  entity: Entity;
  investigationId: string;
  timestamp: string;
  threatIntelligence: AggregatedResult;
  knowledge: AggregatedResult;
}

export function InvestigationHeader({
  entity,
  investigationId,
  timestamp,
  threatIntelligence,
  knowledge,
}: Props) {
  const tiOk = threatIntelligence.providers.filter(
    (p) => p.status === "ok" || p.status === "partial",
  ).length;
  const kbOk = knowledge.providers.filter(
    (p) => p.status === "ok" || p.status === "partial",
  ).length;
  const relCount =
    threatIntelligence.relationships.length + knowledge.relationships.length;
  const refCount =
    threatIntelligence.references.length + knowledge.references.length;

  return (
    <div className="bg-zinc-900 border border-zinc-800 rounded-2xl p-5">
      {/* Entity identity */}
      <div className="flex items-start justify-between gap-4 mb-4">
        <div className="min-w-0 flex-1">
          <p className="text-xs text-zinc-500 mb-1.5">{entityLabel(entity.type)}</p>
          <h1 className="text-xl font-mono font-medium text-white break-all leading-snug">
            {entity.value}
          </h1>
          {entity.normalized_value && entity.normalized_value !== entity.value && (
            <p className="text-xs text-zinc-600 font-mono mt-1 break-all">
              {entity.normalized_value}
            </p>
          )}
        </div>
        <span className="shrink-0 px-2.5 py-1 rounded-full bg-zinc-800 border border-zinc-700 text-xs text-zinc-400">
          {entityLabel(entity.type)}
        </span>
      </div>

      {/* Investigation ID + timestamp */}
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-zinc-600 font-mono mb-3">
        <span
          title={investigationId}
          className="truncate max-w-[200px] sm:max-w-none"
          aria-label={`Investigation ID: ${investigationId}`}
        >
          {investigationId.slice(0, 8)}…
        </span>
        <span className="text-zinc-700">·</span>
        <span className="font-sans text-zinc-500">{timestamp}</span>
      </div>

      {/* Scope stats */}
      <div className="flex flex-wrap items-center gap-x-5 gap-y-2 pt-3 border-t border-zinc-800">
        <Stat label="TI Sources" value={tiOk} />
        <Stat label="Knowledge Sources" value={kbOk} />
        <Stat label="Relationships" value={relCount} />
        <Stat label="References" value={refCount} />
      </div>
    </div>
  );
}

function Stat({ label, value }: { label: string; value: number }) {
  return (
    <span className="text-xs">
      <span className="text-white font-semibold">{value}</span>{" "}
      <span className="text-zinc-500">{label}</span>
    </span>
  );
}
