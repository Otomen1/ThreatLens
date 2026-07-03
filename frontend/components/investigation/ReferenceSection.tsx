"use client";

import { useState } from "react";

import type { AttributedReference } from "@/lib/api";
import { groupReferencesBySource } from "@/lib/investigation";

import { LanguageGroupHeader } from "./shared/DetectionDisclosure";

interface Props {
  references: AttributedReference[];
}

export function ReferenceSection({ references }: Props) {
  const [openSources, setOpenSources] = useState<ReadonlySet<string>>(new Set());

  if (references.length === 0) return null;

  const groups = groupReferencesBySource(references);

  function toggleSource(source: string) {
    setOpenSources((prev) => {
      const next = new Set(prev);
      if (next.has(source)) next.delete(source);
      else next.add(source);
      return next;
    });
  }

  return (
    <section
      className="bg-zinc-900 border border-zinc-800 rounded-2xl p-5"
      aria-label="References"
    >
      <h2 className="text-sm font-semibold text-white mb-4">
        References
        <span className="ml-2 text-xs font-normal text-zinc-500">({references.length})</span>
      </h2>

      <div className="space-y-2">
        {groups.map((group) => (
          <LanguageGroupHeader
            key={group.source}
            id={`ref-source-${group.source}`}
            label={group.label}
            count={group.items.length}
            expanded={openSources.has(group.source)}
            onToggle={() => toggleSource(group.source)}
          >
            <ul className="space-y-2">
              {group.items.map((r) => (
                <li key={r.reference.url} className="flex items-start gap-2">
                  <ExternalIcon />
                  <div className="min-w-0">
                    <a
                      href={r.reference.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-xs text-blue-400 hover:text-blue-300 transition-colors break-all leading-relaxed"
                    >
                      {r.reference.title}
                    </a>
                    {r.reference.description && (
                      <p className="text-[11px] text-zinc-600 mt-0.5">
                        {r.reference.description}
                      </p>
                    )}
                  </div>
                </li>
              ))}
            </ul>
          </LanguageGroupHeader>
        ))}
      </div>
    </section>
  );
}

function ExternalIcon() {
  return (
    <svg
      width="10"
      height="10"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      className="shrink-0 mt-0.5 text-zinc-600"
      aria-hidden
    >
      <path d="M18 13v6a2 2 0 01-2 2H5a2 2 0 01-2-2V8a2 2 0 012-2h6" />
      <polyline points="15 3 21 3 21 9" />
      <line x1="10" y1="14" x2="21" y2="3" />
    </svg>
  );
}
