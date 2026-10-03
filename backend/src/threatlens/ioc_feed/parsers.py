"""Conservative parsing of explicit IOC fields and sections, never general prose."""

import csv
import hashlib
import io
import ipaddress
import json
import re
from urllib.parse import urlsplit, urlunsplit

from ..search.normalize import refang
from ..threat_feed.logic import clean_text
from .models import Indicator, IocType, Vendor

MAX_FILE_BYTES = 2_000_000
MAX_INDICATORS = 5000
TYPES: dict[str, IocType] = {
    "ip": "ipv4",
    "ipv4": "ipv4",
    "ipv6": "ipv6",
    "ip address": "ipv4",
    "domain": "domain",
    "domains": "domain",
    "url": "url",
    "urls": "url",
    "md5": "md5",
    "sha1": "sha1",
    "sha-1": "sha1",
    "sha256": "sha256",
    "sha-256": "sha256",
    "hash": "sha256",
    "sha256 hash": "sha256",
}


def identity(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:32]


def normalize(value: str, declared: str = "") -> Indicator | None:
    original = value.strip().strip("`\"'")
    value = refang(original)
    if not value or len(value) > 2048 or re.search(r"\s", value):
        return None
    kind: IocType
    if re.fullmatch(r"[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}", value):
        kind = "md5" if len(value) == 32 else "sha1" if len(value) == 40 else "sha256"
        value = value.lower()
    else:
        try:
            address = ipaddress.ip_address(value)
            kind = "ipv4" if address.version == 4 else "ipv6"
            value = str(address)
        except ValueError:
            try:
                parts = urlsplit(value)
            except ValueError:
                return None
            if parts.scheme.lower() in {"http", "https"} and parts.hostname:
                if parts.username or parts.password or not parts.netloc or "\\" in value:
                    return None
                try:
                    port = parts.port
                except ValueError:
                    return None
                host = parts.hostname.lower()
                if ":" in host:
                    host = f"[{host}]"
                netloc = host + (f":{port}" if port else "")
                value = urlunsplit(
                    (parts.scheme.lower(), netloc, parts.path, parts.query, parts.fragment)
                )
                kind = "url"
            elif re.fullmatch(
                r"(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}",
                value,
            ):
                if value.lower().endswith((".exe", ".dll", ".txt", ".csv", ".md", ".json", ".pdf")):
                    return None
                kind, value = "domain", value.lower()
            else:
                return None
    expected = TYPES.get(declared.lower().strip())
    if declared and (
        expected is None or (kind != expected and not (declared.lower() == "ip" and kind == "ipv6"))
    ):
        return None
    return Indicator(id=identity(f"{kind}:{value}"), type=kind, value=value, original=original)


def supported_path(vendor: Vendor, path: str) -> bool:
    if len(path) > 350 or not re.fullmatch(r"[A-Za-z0-9_./ ()-]+", path):
        return False
    if any(part in {"", ".", ".."} for part in path.split("/")):
        return False
    lower = path.lower()
    if any(token in lower for token in ("password", "credential", "username", "license")):
        return False
    if lower.endswith((".txt", ".csv", ".json", ".md5", ".sha1", ".sha256")):
        return True
    return lower.endswith(".md") and (vendor == "eset" or "ioc" in lower or "indicator" in lower)


def parse_file(
    vendor: Vendor, path: str, payload: bytes
) -> tuple[tuple[Indicator, ...], tuple[str, ...]]:
    if not supported_path(vendor, path) or len(payload) > MAX_FILE_BYTES:
        raise ValueError("Unsupported or oversized IOC file")
    text = payload.decode("utf-8-sig")
    if "\x00" in text:
        raise ValueError("Binary content")
    candidates: list[tuple[str, str]] = []
    warnings: list[str] = []
    if path.lower().endswith(".csv"):
        csv_rows = csv.reader(io.StringIO(text))
        header = [cell.lower().strip() for cell in next(csv_rows, [])]
        value_at = next(
            (
                i
                for i, v in enumerate(header)
                if v in {"data", "indicator", "value", "ioc", "sha256", "sha1", "md5"}
            ),
            None,
        )
        type_at = next(
            (i for i, v in enumerate(header) if v in {"type", "indicator_type", "ioc_type"}), None
        )
        if value_at is None:
            raise ValueError("Unsupported CSV columns")
        for row in csv_rows:
            if len(row) > value_at:
                declared = (
                    row[type_at]
                    if type_at is not None and len(row) > type_at
                    else header[value_at]
                    if header[value_at] in TYPES
                    else ""
                )
                candidates.append((row[value_at], declared))
    elif path.lower().endswith(".json"):
        document = json.loads(text)
        if (
            vendor == "talos"
            and isinstance(document, dict)
            and isinstance(document.get("objects"), list)
        ):
            mappings = {
                "ipv4-addr:value": "ipv4",
                "ipv6-addr:value": "ipv6",
                "domain-name:value": "domain",
                "url:value": "url",
                "file:hashes.'MD5'": "md5",
                "file:hashes.MD5": "md5",
                "file:hashes.'SHA-1'": "sha1",
                "file:hashes.'SHA-256'": "sha256",
            }
            unsupported = 0
            for obj in document["objects"]:
                if not isinstance(obj, dict) or obj.get("revoked"):
                    continue
                if obj.get("type") == "indicator":
                    # Only exact, simple equality patterns. No pattern execution or inference.
                    match = re.fullmatch(
                        r"\[([A-Za-z0-9_.:'-]+)\s*=\s*'([^']+)'\]", str(obj.get("pattern", ""))
                    )
                    if match and match[1] in mappings:
                        candidates.append((match[2], mappings[match[1]]))
                    else:
                        unsupported += 1
            if unsupported:
                warnings.append(f"{unsupported} non-simple STIX indicator patterns skipped.")
        rows = (
            document
            if isinstance(document, list)
            else document.get("indicators", [])
            if isinstance(document, dict)
            else []
        )
        for row in rows:
            if isinstance(row, dict) and isinstance(row.get("value"), str):
                candidates.append((row["value"], str(row.get("type", ""))))
    else:
        section = False
        declared = path.rsplit(".", 1)[-1] if path.rsplit(".", 1)[-1] in TYPES else ""
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        pure_list = bool(lines) and all(normalize(line, declared) for line in lines)
        for line in text.splitlines():
            stripped = line.strip().strip("`")
            if (
                re.search(
                    r"(?i)\b(indicators? of compromise|iocs?|sha-?256|sha-?1|md5|"
                    r"domains?|ip addresses|urls?)\b",
                    stripped,
                )
                and len(stripped) < 150
                and (stripped.startswith("#") or stripped.endswith(":"))
            ):
                section = True
                continue
            if stripped.startswith("#") or re.fullmatch(
                r"(?i)(references|sources|benign indicators|examples)\s*:?", stripped
            ):
                section = False
                continue
            if stripped.startswith("|") and section:
                cells = [cell.strip() for cell in stripped.strip("|").split("|")]
                # Explicit type/value tables, or a value column within an IOC section.
                if len(cells) > 1 and cells[0].lower() in TYPES:
                    candidates.append((cells[1], cells[0]))
                else:
                    candidates.extend((cell, "") for cell in cells if normalize(cell))
            elif stripped and (section or pure_list or declared):
                # A whole line must be an IOC, or an explicit type: value pair.
                if normalize(stripped, declared):
                    candidates.append((stripped, declared))
                else:
                    pair = re.match(
                        r"(?i)^(ip|ipv4|ipv6|domain|url|md5|sha-?1|sha-?256)\s*:\s*(\S+)$", stripped
                    )
                    if pair:
                        candidates.append((pair[2], pair[1]))
    records: dict[str, Indicator] = {}
    invalid = 0
    for value, declared in candidates:
        record = normalize(value, declared)
        if record:
            records[record.id] = record
        else:
            invalid += 1
        if len(records) > MAX_INDICATORS:
            raise ValueError("IOC count exceeded limit")
    if invalid:
        warnings.append(f"{invalid} unsupported or invalid indicator fields skipped.")
    if not records:
        warnings.append(
            "No supported explicit indicators found; this is not complete vendor coverage."
        )
    return tuple(records.values()), tuple(warnings)


def title_from_path(path: str) -> str:
    if path.rsplit("/", 1)[-1].lower().startswith(("samples.", "readme.", "iocs.")) and "/" in path:
        return clean_text(path.replace("_", " "), limit=200)
    return clean_text(
        path.rsplit("/", 1)[-1].rsplit(".", 1)[0].replace("-", " ").replace("_", " "), limit=200
    )


def article_link(vendor: Vendor, payload: bytes) -> str | None:
    hosts = {
        "talos": {"blog.talosintelligence.com"},
        "unit42": {"unit42.paloaltonetworks.com"},
        "eset": {"www.welivesecurity.com", "welivesecurity.com"},
        "sophoslabs": {"news.sophos.com"},
    }
    for match in re.finditer(r"https://[^\s<>\"']+", payload.decode("utf-8-sig")):
        value = match[0].rstrip("),.;]")
        parsed = urlsplit(value)
        if parsed.hostname in hosts[vendor] and not parsed.username and not parsed.password:
            return value[:2048]
    return None
