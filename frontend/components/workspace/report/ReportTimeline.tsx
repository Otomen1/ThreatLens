// Timeline (Phase 8.4): the existing Timeline projection, rendered as a
// simple table — every event already exists in `graph.timeline.events`,
// verbatim; nothing is re-sorted, re-derived, or backfilled with an
// invented timestamp.

import type { Timeline } from "@/lib/api";
import { severityClasses, severityLabel } from "@/lib/investigation";

export function ReportTimeline({ timeline }: { timeline: Timeline }) {
  return (
    <section className="print:break-inside-avoid" aria-label="Timeline">
      <h2 className="text-sm font-semibold uppercase tracking-wider text-zinc-400 print:text-zinc-600 mb-2">
        Timeline
        <span className="ml-2 font-normal normal-case text-zinc-600 print:text-zinc-500">
          ({timeline.events.length})
        </span>
      </h2>
      {timeline.events.length === 0 ? (
        <p className="text-sm text-zinc-500 print:text-zinc-600">
          No timestamped evidence was found for this investigation — no events to derive a
          timeline from.
        </p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-xs border-collapse">
            <thead>
              <tr className="text-left text-[10px] uppercase tracking-wider text-zinc-500 print:text-zinc-600 border-b border-zinc-800 print:border-zinc-300">
                <th className="py-1 pr-3 font-medium">Timestamp</th>
                <th className="py-1 pr-3 font-medium">Event</th>
                <th className="py-1 pr-3 font-medium">Type</th>
                <th className="py-1 font-medium">Severity</th>
              </tr>
            </thead>
            <tbody>
              {timeline.events.map((event) => (
                <tr
                  key={event.event_id}
                  className="border-b border-zinc-800/60 print:border-zinc-200 align-top print:break-inside-avoid"
                >
                  <td className="py-1.5 pr-3 text-zinc-400 print:text-zinc-700 font-mono whitespace-nowrap">
                    {new Date(event.timestamp).toLocaleString()}
                  </td>
                  <td className="py-1.5 pr-3 text-zinc-200 print:text-black">
                    <div>{event.title}</div>
                    {event.description && (
                      <div className="text-zinc-500 print:text-zinc-600 mt-0.5">
                        {event.description}
                      </div>
                    )}
                  </td>
                  <td className="py-1.5 pr-3 text-zinc-500 print:text-zinc-600 whitespace-nowrap">
                    {event.event_type.replace(/_/g, " ")}
                  </td>
                  <td className="py-1.5 whitespace-nowrap">
                    {event.severity !== null && (
                      <span
                        className={`px-1.5 py-0.5 rounded-full border print:border-zinc-400 print:bg-white text-[10px] ${severityClasses(event.severity)}`}
                      >
                        {severityLabel(event.severity)}
                      </span>
                    )}
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
