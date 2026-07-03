"use client";

import { useId, useState } from "react";

import { getTagPreview } from "@/lib/investigation";

interface TagListProps {
  tags: string[];
  previewCount?: number;
  labelClassName?: string;
  badgeClassName?: string;
}

const DEFAULT_PREVIEW_COUNT = 20;
const DEFAULT_LABEL_CLASSNAME = "text-[11px] text-zinc-500 uppercase tracking-wider";
const DEFAULT_BADGE_CLASSNAME =
  "px-2 py-0.5 rounded-md bg-zinc-800 border border-zinc-700 text-xs text-zinc-400";

/**
 * A "Tags" block that previews a fixed number of badges and discloses the
 * rest on demand. Investigations can accumulate well over 100 deduplicated
 * tags; this keeps the initial render small while preserving every tag and
 * the existing backend order (no sorting, no re-ranking).
 */
export function TagList({
  tags,
  previewCount = DEFAULT_PREVIEW_COUNT,
  labelClassName = DEFAULT_LABEL_CLASSNAME,
  badgeClassName = DEFAULT_BADGE_CLASSNAME,
}: TagListProps) {
  const [expanded, setExpanded] = useState(false);
  const panelId = useId();

  if (tags.length === 0) return null;

  const { visible: preview, hasMore } = getTagPreview(tags, previewCount);
  const visible = expanded ? tags : preview;

  return (
    <div>
      <div className="flex items-baseline justify-between gap-2 mb-2">
        <p className={labelClassName}>Tags</p>
        <span className="text-[11px] text-zinc-600">
          {expanded ? `Showing all ${tags.length}` : `Showing ${visible.length} of ${tags.length}`}
        </span>
      </div>
      <div id={panelId} role="group" aria-label="Tags" className="flex flex-wrap gap-1.5">
        {visible.map((tag, i) => (
          <span key={`${tag}-${i}`} className={badgeClassName}>
            {tag}
          </span>
        ))}
      </div>
      {hasMore && (
        <button
          type="button"
          onClick={() => setExpanded((v) => !v)}
          aria-expanded={expanded}
          aria-controls={panelId}
          className="mt-2 text-xs text-zinc-500 hover:text-zinc-300 transition-colors"
        >
          {expanded ? "Show fewer" : `Show all ${tags.length} tags`}
        </button>
      )}
    </div>
  );
}
