import type { BatchPreviewResponse } from "@/lib/api";

interface Props {
  preview: BatchPreviewResponse;
  pending: BatchPreviewResponse["entities"];
  onRemove: (index: number) => void;
  onStart: () => void;
  onCancel: () => void;
}

export function BatchPreviewPanel({ preview, pending, onRemove, onStart, onCancel }: Props) {
  return (
    <section className="mt-10 w-full max-w-5xl space-y-5 rounded-2xl border border-amber-500/30 bg-zinc-900 p-6" aria-label="Batch confirmation">
      <div>
        <h2 className="text-lg font-semibold text-white">Confirm batch investigation</h2>
        <p className="mt-1 text-sm text-zinc-400">
          {preview.supported} indicators found · {preview.duplicates} duplicates removed · {preview.invalid} invalid candidates · {preview.cached_items ?? 0} cached · about {preview.estimated_uncached_calls ?? preview.estimated_ti_requests} uncached TI requests
        </p>
      </div>
      <p className="text-sm text-amber-300">{preview.quota_warning} Exposure providers and provider-specific limits may change actual usage.</p>
      {preview.quota_warnings?.map((warning) => <p key={warning} className="text-sm text-amber-200">{warning}</p>)}
      <div className="grid gap-2 sm:grid-cols-2">
        {pending.map((entity, index) => (
          <label key={`${entity.type}-${entity.normalized_value}`} className="flex items-center gap-3 rounded-lg border border-zinc-800 p-3 text-sm text-zinc-200">
            <input type="checkbox" checked onChange={() => onRemove(index)} />
            <span className="truncate font-mono">{entity.normalized_value}</span>
            <span className="ml-auto text-xs text-zinc-500">{entity.type}</span>
          </label>
        ))}
      </div>
      <div className="flex gap-3">
        <button type="button" disabled={!pending.length} onClick={onStart} className="rounded-lg bg-sky-600 px-4 py-2 text-sm font-medium text-white disabled:opacity-50 focus-visible:outline focus-visible:outline-2 focus-visible:outline-sky-400">Run {pending.length} selected</button>
        <button type="button" onClick={onCancel} className="rounded-lg border border-zinc-700 px-4 py-2 text-sm text-zinc-300">Cancel</button>
      </div>
    </section>
  );
}
