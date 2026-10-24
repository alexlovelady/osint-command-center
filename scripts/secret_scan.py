"""Scan the working tree for credentials that should never be committed or shipped.

    uv run python scripts/secret_scan.py [--dist]

Pattern-based (high-confidence key formats plus assignments of long random-looking values to secret-ish names). Test fixtures
use obviously fake values and are allow-listed by marker. With --dist it also scans dist/ (the shipped binaries) for the
same patterns. Exit code 1 on any finding.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKIP_DIRS = {".git", "node_modules", ".venv", "target", "dist", "build", "__pycache__", ".mypy_cache", ".ruff_cache", ".pytest_cache",
             "test-results", "playwright-report", "gen", "data"}
SKIP_SUFFIX = {".png", ".ico", ".icns", ".jpg", ".sqlite", ".zip", ".exe", ".lock", ".pyc", ".woff2", ".tgz"}
PATTERNS = {
    "private key block": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----"),
    "AWS access key id": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "GitHub token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    "Slack token": re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
    "OpenAI/Anthropic style key": re.compile(r"\b(?:sk-ant-|sk-)[A-Za-z0-9_-]{32,}\b"),
    "Google API key": re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    "bearer token literal": re.compile(r"(?i)authorization['\"]?\s*[:=]\s*['\"]?bearer\s+[A-Za-z0-9._~+/=-]{24,}"),
    "secret assignment": re.compile(r"(?i)\b(?:api[_-]?key|secret|passwd|password|token)\b['\"]?\s*[:=]\s*['\"][A-Za-z0-9+/_=-]{24,}['\"]"),
}
SELF_TESTS = {"tests/unit/test_secret_scan.py"}  # contains deliberately fake credential-shaped strings
ALLOW_MARKERS = ("e2e-token-local-only", "dev-token-local-only", "SECRETKEY99", "EXAMPLE", "synthetic", "fake", "not-a-real", "xxxx", "TOKEN123")


def scan_text(path: Path, text: str) -> list[str]:
    hits = []
    for i, line in enumerate(text.splitlines(), 1):
        if any(m.lower() in line.lower() for m in ALLOW_MARKERS):
            continue
        for name, rx in PATTERNS.items():
            if rx.search(line):
                hits.append(f"{path.relative_to(ROOT)}:{i}: {name}")
    return hits


def main() -> int:
    roots = [ROOT] + ([ROOT / "dist"] if "--dist" in sys.argv else [])
    hits: list[str] = []
    n = 0
    for base in roots:
        for p in base.rglob("*"):
            if not p.is_file() or p.suffix.lower() in SKIP_SUFFIX and base == ROOT:
                continue
            if base == ROOT and any(part in SKIP_DIRS or part.startswith(".venv") for part in p.relative_to(ROOT).parts[:-1]):
                continue
            if p.stat().st_size > 8 * 1024 * 1024 and p.suffix != ".exe":
                continue
            if base == ROOT and p.relative_to(ROOT).as_posix() in SELF_TESTS:
                continue
            n += 1
            if p.suffix.lower() in (".exe", ".zip"):
                data = p.read_bytes()
                text = data.decode("latin-1")
                for name, rx in PATTERNS.items():
                    if name != "secret assignment" and rx.search(text):
                        hits.append(f"{p.relative_to(ROOT)}: {name} (binary)")
                continue
            try:
                hits += scan_text(p, p.read_text(encoding="utf8"))
            except (UnicodeDecodeError, OSError):
                continue
    print(f"scanned {n} files; findings: {len(hits)}")
    for h in hits:
        print("  " + h)
    return 1 if hits else 0


if __name__ == "__main__":
    raise SystemExit(main())
