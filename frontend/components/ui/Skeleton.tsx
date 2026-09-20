export function Skeleton({ className = "h-12" }: { className?: string }) {
  return <div aria-hidden="true" className={`skeleton rounded-xl bg-zinc-900 ${className}`} />;
}

export function LoadingRows({ rows = 3, label = "Loading" }: { rows?: number; label?: string }) {
  return <div role="status" aria-label={label} className="space-y-2">{Array.from({ length: rows }, (_, index) => <Skeleton key={index} className="h-16 border border-zinc-800" />)}</div>;
}
