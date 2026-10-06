export function ResourceNotice({ name, loading, error, retry }: {
  name: string; loading: boolean; error: boolean; retry: () => void;
}) {
  if (!loading && !error) return null;
  return <div className="flex flex-wrap items-center gap-3 text-xs text-zinc-400" role="status">
    <p>{loading ? `Loading ${name}…` : `Couldn't load ${name}. Previously loaded information is retained.`}</p>
    {error && !loading && <button type="button" className="rounded border border-zinc-700 px-3 py-2 text-sky-300" onClick={retry}>Retry {name}</button>}
  </div>;
}
