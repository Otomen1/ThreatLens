from datetime import UTC, datetime

from threatlens.threat_feed.logic import classify_region, classify_topic, deterministic_summary
from threatlens.threat_feed.models import FeedRegion, FeedTopic, SourceEntry
from threatlens.threat_feed.sources import parse_rss


def entry(title: str, excerpt: str = "") -> SourceEntry:
    return SourceEntry(
        title=title,
        excerpt=excerpt,
        url="https://example.test/report",
        published_at=datetime(2026, 9, 16, tzinfo=UTC),
    )


def test_malaysia_takes_precedence_over_southeast_asia() -> None:
    item = entry("Malaysia and Singapore issue joint cyber advisory")
    region, relevance, reasons = classify_region("global", item)
    assert region == FeedRegion.MALAYSIA
    assert relevance == "medium"
    assert reasons


def test_topic_and_summary_are_deterministic() -> None:
    item = entry("CVE-2026-1234 actively exploited", "Apply the vendor update immediately.")
    topic = classify_topic(item)
    assert topic == FeedTopic.ACTIVE_EXPLOITATION
    assert deterministic_summary(item, topic) == deterministic_summary(item, topic)


def test_atom_parser_preserves_source_metadata() -> None:
    payload = """<feed xmlns="http://www.w3.org/2005/Atom"><entry><id>one</id>
    <title>Security advisory for Example</title><summary>Install the update.</summary>
    <link href="https://example.test/one"/><updated>2026-09-16T10:00:00Z</updated>
    </entry></feed>"""
    parsed = parse_rss(payload.encode())
    assert len(parsed) == 1
    assert parsed[0].guid == "one"
    assert parsed[0].url == "https://example.test/one"
