// Pure data utilities for the Investigation Workspace.
// No JSX — safe to import from both server and client components.

import type {
  AggregatedResult,
  AttributedEvidence,
  AttributedReference,
  AttributedRelationship,
  Entity,
  EntityType,
  ProviderSummary,
  ReputationLevel,
  ResultStatus,
} from "./api";

// --- entity classification ---

const IOC_SET: ReadonlySet<EntityType> = new Set([
  "ipv4", "ipv6", "domain", "url", "email", "md5", "sha1", "sha256",
]);

const REFERENCE_SET: ReadonlySet<EntityType> = new Set([
  "mitre_technique", "threat_actor", "malware_family", "cve", "cwe", "capec",
]);

export function isIocType(type: EntityType): boolean {
  return IOC_SET.has(type);
}

export function isReferenceType(type: EntityType): boolean {
  return REFERENCE_SET.has(type);
}

// --- labels ---

export const ENTITY_LABELS: Record<EntityType, string> = {
  ipv4: "IPv4 Address",
  ipv6: "IPv6 Address",
  domain: "Domain",
  url: "URL",
  email: "Email Address",
  md5: "MD5 Hash",
  sha1: "SHA-1 Hash",
  sha256: "SHA-256 Hash",
  cve: "CVE",
  cwe: "CWE",
  capec: "CAPEC",
  mitre_technique: "MITRE ATT&CK Technique",
  registry_key: "Registry Key",
  process_name: "Process Name",
  powershell_command: "PowerShell Command",
  windows_api: "Windows API",
  file_name: "File Name",
  threat_actor: "Threat Actor",
  malware_family: "Malware Family",
  freetext: "Free Text",
  unknown: "Unknown",
};

export function entityLabel(type: EntityType): string {
  return ENTITY_LABELS[type] ?? type;
}

export function reputationLabel(level: ReputationLevel): string {
  const labels: Record<ReputationLevel, string> = {
    unknown: "Unknown",
    benign: "Benign",
    likely_benign: "Likely Benign",
    suspicious: "Suspicious",
    likely_malicious: "Likely Malicious",
    malicious: "Malicious",
  };
  return labels[level] ?? level;
}

export function statusLabel(status: ResultStatus): string {
  const labels: Record<ResultStatus, string> = {
    ok: "OK",
    not_found: "Not Found",
    unsupported: "Unsupported",
    partial: "Partial",
    error: "Error",
    timeout: "Timeout",
    rate_limited: "Rate Limited",
    unauthorized: "Unauthorized",
  };
  return labels[status] ?? status;
}

// --- Tailwind color utilities ---

export function reputationClasses(level: ReputationLevel): string {
  switch (level) {
    case "malicious":
    case "likely_malicious":
      return "text-red-400 bg-red-500/10 border-red-500/30";
    case "suspicious":
      return "text-amber-400 bg-amber-500/10 border-amber-500/30";
    case "benign":
    case "likely_benign":
      return "text-emerald-400 bg-emerald-500/10 border-emerald-500/30";
    default:
      return "text-zinc-400 bg-zinc-700/20 border-zinc-600/40";
  }
}

export function statusDotClass(status: ResultStatus): string {
  switch (status) {
    case "ok":
      return "bg-emerald-400";
    case "partial":
      return "bg-amber-400";
    case "rate_limited":
    case "unauthorized":
      return "bg-amber-400";
    case "error":
    case "timeout":
      return "bg-red-400";
    default:
      return "bg-zinc-500";
  }
}

export function statusClasses(status: ResultStatus): string {
  switch (status) {
    case "ok":
      return "text-emerald-400 border-emerald-500/30 bg-emerald-500/10";
    case "partial":
      return "text-amber-400 border-amber-500/30 bg-amber-500/10";
    case "error":
    case "timeout":
      return "text-red-400 border-red-500/30 bg-red-500/10";
    case "rate_limited":
    case "unauthorized":
      return "text-amber-400 border-amber-500/30 bg-amber-500/10";
    default:
      return "text-zinc-400 border-zinc-600/40 bg-zinc-700/20";
  }
}

// --- reputation helpers ---

const REPUTATION_ORDER: ReputationLevel[] = [
  "malicious",
  "likely_malicious",
  "suspicious",
  "likely_benign",
  "benign",
  "unknown",
];

export function worstReputation(providers: ProviderSummary[]): ReputationLevel | null {
  for (const level of REPUTATION_ORDER) {
    if (providers.some((p) => p.reputation?.level === level)) return level;
  }
  return null;
}

// --- attribution helpers ---

export function evidenceByProvider(
  evidence: AttributedEvidence[],
  provider: string,
): AttributedEvidence[] {
  return evidence.filter((e) => e.sources.includes(provider));
}

export function relationshipsByProvider(
  relationships: AttributedRelationship[],
  provider: string,
): AttributedRelationship[] {
  return relationships.filter((r) => r.sources.includes(provider));
}

export function referencesByProvider(
  references: AttributedReference[],
  provider: string,
): AttributedReference[] {
  return references.filter((r) => r.sources.includes(provider));
}

// --- key attribute extraction for ThreatSummaryCard ---

export interface KeyAttribute {
  label: string;
  value: string;
}

// Evidence types shown in the summary card (informational; not diagnostic)
const SUMMARY_TYPES = new Set([
  "abuse_confidence",
  "other",
  "category",
  "first_seen",
  "last_seen",
  "malware_family",
]);

// Evidence types excluded from the summary (they appear in dedicated sections)
const SKIP_TYPES = new Set([
  "tag",
  "classification",
  "detection",
  "pulse_match",
  "sandbox_observation",
  "blocklist",
  "communication",
]);

// Summary labels too noisy or redundant for the summary card
const SKIP_LABELS = new Set(["distinct reporters"]);

export function extractKeyAttributes(
  entity: Entity,
  ti: AggregatedResult,
  kb: AggregatedResult,
): KeyAttribute[] {
  const attrs: KeyAttribute[] = [];

  if (isIocType(entity.type)) {
    for (const { evidence } of ti.evidence) {
      if (attrs.length >= 8) break;
      if (SKIP_TYPES.has(evidence.type)) continue;
      if (!SUMMARY_TYPES.has(evidence.type)) continue;
      // Evidence summaries follow the "Label: value" convention
      const sep = evidence.summary.indexOf(": ");
      if (sep === -1) continue;
      const label = evidence.summary.slice(0, sep);
      const value = evidence.summary.slice(sep + 2);
      if (SKIP_LABELS.has(label.toLowerCase())) continue;
      attrs.push({ label, value });
    }
  } else if (entity.type === "mitre_technique") {
    const meta = kb.metadata["mitre_attack"] as Record<string, unknown> | undefined;
    if (meta) {
      const tactics = meta.tactics as string[] | undefined;
      if (tactics?.length) attrs.push({ label: "Tactics", value: tactics.join(", ") });

      const platforms = meta.platforms as string[] | undefined;
      if (platforms?.length) attrs.push({ label: "Platforms", value: platforms.join(", ") });

      if (meta.is_subtechnique && meta.parent_technique) {
        attrs.push({ label: "Parent Technique", value: String(meta.parent_technique) });
      }

      const subTechs = meta.sub_techniques as string[] | undefined;
      if (subTechs?.length) {
        attrs.push({ label: "Sub-techniques", value: String(subTechs.length) });
      }

      const mitigations = meta.mitigations as unknown[] | undefined;
      if (mitigations?.length) {
        attrs.push({ label: "Mitigations", value: String(mitigations.length) });
      }
    }
  } else if (entity.type === "cve") {
    const meta = kb.metadata["nvd"] as Record<string, unknown> | undefined;
    if (meta) {
      const cvss = meta.cvss as Record<string, unknown> | undefined;
      if (cvss) {
        attrs.push({ label: "CVSS Score", value: `${cvss.base_score} (${cvss.base_severity})` });
        if (cvss.attack_vector) attrs.push({ label: "Attack Vector", value: String(cvss.attack_vector) });
        if (cvss.attack_complexity) attrs.push({ label: "Attack Complexity", value: String(cvss.attack_complexity) });
        if (cvss.privileges_required) attrs.push({ label: "Privileges Required", value: String(cvss.privileges_required) });
        if (cvss.user_interaction) attrs.push({ label: "User Interaction", value: String(cvss.user_interaction) });
      }
      if (meta.published) attrs.push({ label: "Published", value: String(meta.published) });
      if (meta.last_modified) attrs.push({ label: "Last Modified", value: String(meta.last_modified) });
      const cwes = meta.cwes as string[] | undefined;
      if (cwes?.length) attrs.push({ label: "Weaknesses", value: cwes.join(", ") });
      const products = meta.affected_products as unknown[] | undefined;
      if (products?.length) attrs.push({ label: "Affected Products", value: String(products.length) });
    }
  } else if (entity.type === "cwe") {
    const meta = kb.metadata["cwe"] as Record<string, unknown> | undefined;
    if (meta) {
      if (meta.likelihood_of_exploit)
        attrs.push({ label: "Likelihood", value: String(meta.likelihood_of_exploit) });
      const platforms = meta.applicable_platforms as string[] | undefined;
      if (platforms?.length)
        attrs.push({ label: "Platforms", value: platforms.slice(0, 3).join(", ") });
      const consequences = meta.common_consequences as unknown[] | undefined;
      if (consequences?.length)
        attrs.push({ label: "Consequences", value: String(consequences.length) });
      const mitigations = meta.mitigations as unknown[] | undefined;
      if (mitigations?.length)
        attrs.push({ label: "Mitigations", value: String(mitigations.length) });
      const capecs = meta.related_attack_patterns as string[] | undefined;
      if (capecs?.length)
        attrs.push({ label: "Related CAPEC", value: capecs.slice(0, 4).join(", ") });
    }
  } else if (entity.type === "capec") {
    const meta = kb.metadata["capec"] as Record<string, unknown> | undefined;
    if (meta) {
      if (meta.typical_severity)
        attrs.push({ label: "Severity", value: String(meta.typical_severity) });
      if (meta.likelihood_of_attack)
        attrs.push({ label: "Likelihood", value: String(meta.likelihood_of_attack) });
      if (meta.abstraction)
        attrs.push({ label: "Abstraction", value: String(meta.abstraction) });
      const weaknesses = meta.related_weaknesses as string[] | undefined;
      if (weaknesses?.length)
        attrs.push({ label: "Weaknesses", value: weaknesses.slice(0, 4).join(", ") });
      const techniques = meta.related_techniques as string[] | undefined;
      if (techniques?.length)
        attrs.push({ label: "ATT&CK Techniques", value: techniques.slice(0, 4).join(", ") });
      const mitigations = meta.mitigations as unknown[] | undefined;
      if (mitigations?.length)
        attrs.push({ label: "Mitigations", value: String(mitigations.length) });
    }
  } else if (entity.type === "threat_actor" || entity.type === "malware_family") {
    if (kb.tags.length > 0) {
      attrs.push({ label: "Aliases", value: kb.tags.slice(0, 6).join(", ") });
    }
    const techCount = kb.relationships.filter(
      (r) => r.relationship.target_type === "attack_pattern",
    ).length;
    if (techCount > 0) attrs.push({ label: "Known Techniques", value: String(techCount) });

    const groupCount = kb.relationships.filter(
      (r) => r.relationship.target_type === "threat_actor",
    ).length;
    if (groupCount > 0) attrs.push({ label: "Associated Groups", value: String(groupCount) });

    const softCount = kb.relationships.filter(
      (r) =>
        r.relationship.target_type === "malware_family" ||
        r.relationship.target_type === "tool",
    ).length;
    if (softCount > 0) attrs.push({ label: "Associated Software", value: String(softCount) });
  }

  return attrs;
}

// --- relationship / reference formatting ---

export function formatRelationship(rel: string): string {
  return rel.replace(/_/g, " ");
}

export function formatTargetType(targetType: string): string {
  const labels: Record<string, string> = {
    attack_pattern: "Technique",
    threat_actor: "Threat Actor",
    malware_family: "Malware",
    tool: "Tool",
    campaign: "Campaign",
    vulnerability: "CVE",
    weakness: "CWE",
    domain: "Domain",
    ipv4: "IPv4",
    ipv6: "IPv6",
    url: "URL",
  };
  return labels[targetType] ?? targetType.replace(/_/g, " ");
}

// --- misc ---

export function truncate(text: string, maxLen: number): string {
  if (text.length <= maxLen) return text;
  return text.slice(0, maxLen).trimEnd() + "…";
}
