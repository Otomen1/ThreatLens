"""Fail CI when committed source contains a high-confidence credential pattern."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATTERNS = {
    "private key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "Supabase secret": re.compile(r"\bsb_secret_[A-Za-z0-9_-]{16,}"),
    "GitHub token": re.compile(r"\b(?:ghp|github_pat)_[A-Za-z0-9_]{20,}"),
    "credentialed PostgreSQL URL": re.compile(r"postgres(?:ql)?://[^:\s]+:[^@\s\[]+@"),
}
IGNORED_SUFFIXES = {".lock", ".png", ".jpg", ".jpeg", ".gif", ".pdf"}


def tracked_files() -> list[Path]:
    output = subprocess.run(
        ["git", "ls-files", "-z"], cwd=ROOT, check=True, capture_output=True
    ).stdout.decode()
    return [ROOT / item for item in output.split("\0") if item]


def main() -> int:
    findings: list[str] = []
    for path in tracked_files():
        if path.suffix.lower() in IGNORED_SUFFIXES or not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for name, pattern in PATTERNS.items():
            if pattern.search(text):
                findings.append(f"{path.relative_to(ROOT)}: possible {name}")
    if findings:
        print("Credential scan failed:")
        print("\n".join(findings))
        return 1
    print("Credential scan passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
