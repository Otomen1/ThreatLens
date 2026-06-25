export default function HomePage() {
  return (
    <main className="min-h-screen flex flex-col items-center justify-center px-4">
      <div className="w-full max-w-2xl space-y-10">
        {/* Logo + heading */}
        <div className="text-center space-y-3">
          <div className="inline-flex items-center justify-center w-12 h-12 rounded-xl bg-zinc-800 border border-zinc-700 mb-2">
            <svg
              width="24"
              height="24"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.5"
              strokeLinecap="round"
              strokeLinejoin="round"
              className="text-zinc-300"
            >
              <circle cx="11" cy="11" r="8" />
              <path d="m21 21-4.35-4.35" />
              <path d="M11 8v6M8 11h6" />
            </svg>
          </div>
          <h1 className="text-3xl font-semibold text-white tracking-tight">
            ThreatLens
          </h1>
          <p className="text-zinc-500 text-sm leading-relaxed max-w-md mx-auto">
            Search any indicator, technique, actor, or vulnerability.
            <br />
            Understand it instantly.
          </p>
        </div>

        {/* Search box */}
        <div className="relative group">
          <div className="absolute inset-0 rounded-2xl bg-gradient-to-r from-zinc-700/30 to-zinc-600/20 blur-sm group-hover:blur-md transition-all duration-300 opacity-0 group-hover:opacity-100" />
          <div className="relative flex items-center bg-zinc-900 border border-zinc-800 rounded-2xl overflow-hidden transition-colors focus-within:border-zinc-600">
            <svg
              width="16"
              height="16"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
              className="absolute left-5 text-zinc-600 shrink-0"
            >
              <circle cx="11" cy="11" r="8" />
              <path d="m21 21-4.35-4.35" />
            </svg>
            <input
              type="text"
              placeholder="8.8.8.8 · emotet · T1059.001 · CVE-2024-3094 · rundll32.exe…"
              className="w-full bg-transparent pl-12 pr-32 py-4 text-white placeholder-zinc-700 text-sm focus:outline-none font-mono"
              disabled
            />
            <button
              disabled
              className="absolute right-3 bg-zinc-800 hover:bg-zinc-700 border border-zinc-700 text-zinc-300 text-xs font-medium px-4 py-2 rounded-xl transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              Search
            </button>
          </div>
        </div>

        {/* Entity type pills */}
        <div className="flex flex-wrap justify-center gap-2">
          {[
            "IP Address",
            "Domain",
            "File Hash",
            "CVE",
            "MITRE Technique",
            "Malware Family",
            "Threat Actor",
            "Registry Key",
          ].map((type) => (
            <span
              key={type}
              className="px-3 py-1 bg-zinc-900 border border-zinc-800 rounded-full text-zinc-600 text-xs"
            >
              {type}
            </span>
          ))}
        </div>

        {/* Status */}
        <div className="text-center space-y-1">
          <p className="text-zinc-700 text-xs">
            Phase 1 in development — Universal Search Engine
          </p>
        </div>
      </div>
    </main>
  );
}
