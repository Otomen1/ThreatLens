export function DataLocation({ kind, detail }: { kind: "Temporary" | "Browser-local" | "Saved to database"; detail?: string }) {
  return <p className="text-xs text-zinc-500"><span className="rounded border border-zinc-700 px-2 py-0.5">{kind}</span>{detail && <span className="ml-2">{detail}</span>}</p>;
}
