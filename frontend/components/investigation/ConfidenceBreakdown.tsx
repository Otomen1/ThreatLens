import type { Confidence } from "@/lib/api";
import { confidenceBandClasses, confidenceBandLabel } from "@/lib/investigation";

interface Props {
  confidence: Confidence;
}

/**
 * Confidence visualization — band + score, contested flag, and the four
 * deterministic factor contributions as simple horizontal bars. Every number
 * comes straight from the backend; nothing is recomputed.
 */
export function ConfidenceBreakdown({ confidence }: Props) {
  const { score, band, contested, factors } = confidence;
  const total = factors.reduce((sum, f) => sum + Math.max(0, f.contribution), 0) || 1;

  return (
    <div className="space-y-2">
      <div className="flex items-center gap-2">
        <span
          className={`px-2 py-0.5 rounded-md border text-xs font-medium ${confidenceBandClasses(band)}`}
        >
          {confidenceBandLabel(band)} · {score}
        </span>
        {contested && (
          <span className="px-2 py-0.5 rounded-md border text-xs text-amber-400 bg-amber-500/10 border-amber-500/30">
            Contested
          </span>
        )}
      </div>

      <div className="space-y-1.5">
        {factors.map((factor, i) => (
          <div key={i}>
            <div className="flex items-center justify-between text-[11px]">
              <span className="text-zinc-400 capitalize">{factor.name}</span>
              <span className="text-zinc-600">{factor.contribution} pts</span>
            </div>
            <div className="h-1.5 rounded-full bg-zinc-800 overflow-hidden" aria-hidden>
              <div
                className="h-full bg-zinc-500 rounded-full"
                style={{
                  width: `${Math.min(100, Math.max(0, (factor.contribution / total) * 100))}%`,
                }}
              />
            </div>
            {factor.detail && (
              <p className="text-[10px] text-zinc-600 mt-0.5 leading-relaxed">{factor.detail}</p>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
