/** CSS-only loading artwork; the containing status supplies its accessible label. */
export function SearchLoadingIcon() {
  return <span aria-hidden="true" className="search-loading-tile inline-flex h-12 w-12 shrink-0 items-center justify-center rounded-xl border border-zinc-700 bg-zinc-800 text-zinc-300">
    <span className="search-loading-lens inline-flex">
      <svg width="26" height="26" viewBox="0 0 26 26" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round">
        <circle cx="11" cy="11" r="7.5" />
        <path d="m16.5 16.5 6 6M11 8v6M8 11h6" />
      </svg>
    </span>
  </span>;
}

export function SearchLoading({ label = "Loading results…" }: { label?: string }) {
  return <div role="status" aria-live="polite" className="flex flex-col items-center gap-3 py-4 text-sm text-zinc-400">
    <SearchLoadingIcon />
    <span>{label}</span>
  </div>;
}
