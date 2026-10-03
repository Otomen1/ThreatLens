"""Explicit metadata context only; geography is never inferred from hosting."""

import json
import re
from html import unescape

from pydantic import BaseModel


class TargetingEvidence(BaseModel):
    region: str
    source: str
    field: str
    excerpt: str
    related_report: bool = False


def targeting(
    source: str, fields: dict[str, str], *, related_report: bool = False
) -> tuple[TargetingEvidence, ...]:
    regions = (
        ("malaysia", r"Malaysia(?:n)?"),
        (
            "southeast_asia",
            r"Southeast Asia|South-East Asia|ASEAN|Singapore(?:an)?|Indonesia(?:n)?|"
            r"Thailand|Thai|Philippines|Filipino|Vietnam(?:ese)?|Brunei|Cambodia(?:n)?|Laos|Myanmar",
        ),
    )
    for region, names in regions:
        for field, text in fields.items():
            cleaned = unescape(re.sub(r"<[^>]+>", " ", text))[:4000]
            for sentence in re.split(r"(?<=[.!?])\s+|\n", cleaned):
                pattern = (
                    r"\b(?:target(?:s|ed|ing)?|affect(?:s|ed|ing)?|attacks? on|"
                    r"victims? in)\s+(?:[\w'-]+\s+){0,5}(?:" + names + r")\b"
                )
                if re.search(pattern, sentence, re.I) and not re.search(
                    r"\b(?:not|never|no evidence|didn't|doesn't)\b", sentence, re.I
                ):
                    return (
                        TargetingEvidence(
                            region=region,
                            source=source,
                            field=field,
                            excerpt=sentence[:500],
                            related_report=related_report,
                        ),
                    )
    return ()


def explicit_cves(payload: bytes, path: str) -> tuple[str, ...]:
    text = payload.decode("utf-8-sig")
    values: set[str] = set()
    if path.lower().endswith(".json"):
        document = json.loads(text)

        def walk(node: object, depth: int = 0) -> None:
            if depth > 16:
                return
            if isinstance(node, dict):
                for key, value in node.items():
                    if str(key).lower() in {"cve", "cves", "cve_id", "cve_ids"}:
                        entries = value if isinstance(value, list) else [value]
                        for entry in entries:
                            if isinstance(entry, str) and re.fullmatch(
                                r"CVE-\d{4}-\d{4,20}", entry.strip(), re.I
                            ):
                                values.add(entry.strip().upper())
                    if (
                        node.get("source_name") == "cve"
                        and key == "external_id"
                        and isinstance(value, str)
                        and re.fullmatch(r"CVE-\d{4}-\d{4,20}", value, re.I)
                    ):
                        values.add(value.upper())
                    walk(value, depth + 1)
            elif isinstance(node, list):
                for item in node:
                    walk(item, depth + 1)

        walk(document)
    else:
        for line in text.splitlines():
            if re.match(r"(?i)^\s*(?:#+\s*)?CVE(?:s| IDs?)?\s*:", line):
                values.update(m.upper() for m in re.findall(r"CVE-\d{4}-\d{4,20}\b", line, re.I))
    return tuple(sorted(values))[:100]


def source_context(payload: bytes, path: str) -> str:
    text = payload.decode("utf-8-sig")
    if path.lower().endswith(".json"):
        document = json.loads(text)
        if not isinstance(document, dict):
            return ""
        return "\n".join(
            str(document[key])[:1000]
            for key in ("title", "summary", "targeting", "affected_audience")
            if isinstance(document.get(key), str)
        )[:4000]
    return "\n".join(
        line
        for line in text.splitlines()
        if re.match(
            r"(?i)^\s*(?:#+\s*)?(?:title|summary|targeting|"
            r"affected audience)\s*:",
            line,
        )
    )[:4000]
