import { notFound } from "next/navigation";
import { ThreatFeedShell } from "@/components/threat-feed/ThreatFeedShell";
import { newsRegionFromSlug } from "@/lib/newsFeed";

export default async function RegionalNewsPage({ params }: { params: Promise<{ region: string }> }) {
  const { region: slug } = await params;
  const region = newsRegionFromSlug(slug);
  if (!region) notFound();
  return <ThreatFeedShell region={region} />;
}
