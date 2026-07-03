import type { AggregatedResult, Entity } from "@/lib/api";
import { extractKeyAttributes, groupKeyAttributes } from "@/lib/investigation";

import { TagList } from "./shared/TagList";

interface Props {
  entity: Entity;
  threatIntelligence: AggregatedResult;
  knowledge: AggregatedResult;
}

export function ThreatSummaryCard({ entity, threatIntelligence, knowledge }: Props) {
  const attrs = extractKeyAttributes(entity, threatIntelligence, knowledge);
  const groups = groupKeyAttributes(attrs);

  // Deduplicated tags from both frameworks
  const seenTags = new Set<string>();
  const tags: string[] = [];
  for (const tag of [...threatIntelligence.tags, ...knowledge.tags]) {
    const key = tag.toLowerCase();
    if (!seenTags.has(key)) {
      seenTags.add(key);
      tags.push(tag);
    }
  }

  if (attrs.length === 0 && tags.length === 0) return null;

  return (
    <div className="bg-zinc-900 border border-zinc-800 rounded-2xl p-5 h-full">
      <h2 className="text-[11px] font-medium text-zinc-500 uppercase tracking-wider mb-4">
        Key Attributes
      </h2>

      <div className="space-y-4">
        {groups.map((group, i) => (
          <div key={group.category} className={i > 0 ? "pt-4 border-t border-zinc-800" : ""}>
            <p className="text-[11px] text-zinc-500 mb-2">{group.category}</p>
            <dl className="space-y-2.5">
              {group.items.map(({ label, value }) => (
                <div key={label} className="flex items-baseline justify-between gap-4 text-sm">
                  <dt className="text-zinc-500 shrink-0 text-xs">{label}</dt>
                  <dd className="text-zinc-300 text-right text-xs font-mono break-all">{value}</dd>
                </div>
              ))}
            </dl>
          </div>
        ))}

        {tags.length > 0 && (
          <div className={groups.length > 0 ? "pt-4 border-t border-zinc-800" : ""}>
            <TagList tags={tags} labelClassName="text-[11px] text-zinc-500" />
          </div>
        )}
      </div>
    </div>
  );
}
