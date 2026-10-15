"""Strict metadata-only parsing of the official NC4 advisory listing."""

import re
from datetime import UTC, datetime, timedelta, timezone
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from .logic import clean_text
from .models import SourceEntry


class ListingParser(HTMLParser):
    def __init__(self, base_url: str, limit: int) -> None:
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.limit = limit
        self.rows: dict[str, SourceEntry] = {}
        self.url = ""
        self.title: list[str] = []
        self.excerpt: list[str] = []
        self.text: list[str] = []
        self.field = ""
        self.field_tag = ""

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if tag == "a" and not self.url:
            url = urljoin(self.base_url, values.get("href") or "")
            parsed = urlsplit(url)
            if (
                parsed.scheme == "https"
                and parsed.netloc == urlsplit(self.base_url).netloc
                and re.fullmatch(r"/alertAdvisory-detail/NC4-ALR-\d{4}-\d+", parsed.path)
                and "aa-card-link" in (values.get("class") or "").split()
            ):
                self.url, self.title, self.excerpt, self.text = url, [], [], []
        if self.url:
            classes = (values.get("class") or "").split()
            if "card-title" in classes or "card-para" in classes:
                self.field = "title" if "card-title" in classes else "excerpt"
                self.field_tag = tag

    def handle_data(self, data: str) -> None:
        if self.url:
            self.text.append(data)
            if self.field == "title":
                self.title.append(data)
            elif self.field == "excerpt":
                self.excerpt.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == self.field_tag:
            self.field, self.field_tag = "", ""
        if tag != "a" or not self.url:
            return
        title = clean_text(" ".join(self.title), limit=500)
        date = re.search(r"\b\d{1,2} [A-Za-z]{3,9} \d{4}\b", " ".join(self.text))
        if title and date and len(self.rows) < self.limit:
            for pattern in ("%d %b %Y", "%d %B %Y"):
                try:
                    published = (
                        datetime.strptime(date[0], pattern)
                        .replace(tzinfo=timezone(timedelta(hours=8)))
                        .astimezone(UTC)
                    )
                    self.rows[self.url] = SourceEntry(
                        title=title,
                        excerpt=clean_text(" ".join(self.excerpt)),
                        url=self.url,
                        published_at=published,
                    )
                    break
                except ValueError:
                    continue
        self.url = ""
        self.field, self.field_tag = "", ""


def parse_listing(payload: str, base_url: str, *, limit: int) -> tuple[SourceEntry, ...]:
    parser = ListingParser(base_url, limit)
    parser.feed(payload)
    return tuple(parser.rows.values())
