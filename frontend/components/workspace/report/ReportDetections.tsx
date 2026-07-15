// Detection Outputs (Phase 8.4): only rendered when a DetectionPackage is
// already attached to the saved record — Detection Engineering is never
// re-run during report generation. The caller omits this section entirely
// when `detection_package` is null (see report/page.tsx).

import type { DetectionPackage } from "@/lib/api";

export function ReportDetections({ pkg }: { pkg: DetectionPackage }) {
  return (
    <section className="print:break-inside-avoid" aria-label="Detection outputs">
      <h2 className="text-sm font-semibold uppercase tracking-wider text-zinc-400 print:text-zinc-600 mb-2">
        Detection Outputs
        <span className="ml-2 font-normal normal-case text-zinc-600 print:text-zinc-500">
          ({pkg.artifacts.length})
        </span>
      </h2>
      {pkg.artifacts.length === 0 ? (
        <p className="text-sm text-zinc-500 print:text-zinc-600">
          No detection artifacts were generated for this investigation.
        </p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-xs border-collapse">
            <thead>
              <tr className="text-left text-[10px] uppercase tracking-wider text-zinc-500 print:text-zinc-600 border-b border-zinc-800 print:border-zinc-300">
                <th className="py-1 pr-3 font-medium">Title</th>
                <th className="py-1 pr-3 font-medium">Language</th>
                <th className="py-1 font-medium">Category</th>
              </tr>
            </thead>
            <tbody>
              {pkg.artifacts.map((artifact) => (
                <tr
                  key={artifact.id}
                  className="border-b border-zinc-800/60 print:border-zinc-200"
                >
                  <td className="py-1.5 pr-3 text-zinc-200 print:text-black break-words">
                    {artifact.title}
                  </td>
                  <td className="py-1.5 pr-3 text-zinc-500 print:text-zinc-600 whitespace-nowrap">
                    {artifact.language}
                  </td>
                  <td className="py-1.5 text-zinc-500 print:text-zinc-600 whitespace-nowrap">
                    {artifact.category}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
