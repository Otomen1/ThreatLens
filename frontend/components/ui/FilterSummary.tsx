export type ActiveFilter = { key: string; label: string; value: string; remove: () => void };

export function FilterSummary({ filters, reset }: { filters: ActiveFilter[]; reset: () => void }) {
  return <div aria-label="Active filters" className="flex flex-wrap items-center gap-2 text-xs">
    <span className="rounded-full border border-zinc-700 bg-zinc-900 px-2.5 py-1 text-zinc-400">{filters.length} {filters.length === 1 ? "filter" : "filters"} active</span>
    {filters.map((filter) => <button type="button" key={filter.key} aria-label={`Remove ${filter.label} filter`} onClick={filter.remove} className="max-w-full break-all rounded-lg border border-zinc-700 px-2.5 py-1 text-zinc-300 hover:bg-zinc-800">{filter.label}: {filter.value} <span aria-hidden="true">×</span></button>)}
    {filters.length > 0 && <button type="button" onClick={reset} className="rounded-lg border border-zinc-700 px-3 py-1 text-zinc-300 hover:bg-zinc-800">Reset filters</button>}
  </div>;
}
