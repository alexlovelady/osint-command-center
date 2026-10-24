"""Licence inventory for what ships (Python runtime deps, web runtime deps, Rust crates) + a Rust CycloneDX SBOM.

    uv run python scripts/license_audit.py

Writes docs/license-audit.md and docs/supply-chain/sbom-rust.cdx.json. Classification is by SPDX-ish text; anything it cannot
classify is listed as NEEDS REVIEW rather than assumed fine. This is an inventory, not legal advice.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from collections import Counter, defaultdict
from importlib import metadata
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / "apps" / "web"
TAURI = ROOT / "apps" / "desktop" / "src-tauri"
PERMISSIVE = re.compile(r"\b(MIT|BSD|Apache|ISC|Unlicense|Zlib|0BSD|CC0|PSF|Python-2\.0|MPL|BlueOak|CC-BY|Unicode|OpenSSL|BSL)\b", re.IGNORECASE)
COPYLEFT = re.compile(r"\b(GPL|AGPL|LGPL|SSPL|EUPL|CPAL|OSL)\b", re.IGNORECASE)


def classify(lic: str) -> str:
    if not lic or lic.lower() in ("unknown", "none"):
        return "NEEDS REVIEW"
    if COPYLEFT.search(lic) and not re.search(r"\b(MIT|Apache|BSD)\b", lic, re.IGNORECASE):
        return "COPYLEFT (review)"
    if PERMISSIVE.search(lic):
        return "permissive" if not COPYLEFT.search(lic) else "permissive-or-copyleft (choose permissive)"
    return "NEEDS REVIEW"


def python_deps() -> list[tuple[str, str, str]]:
    req = subprocess.run(["uv", "export", "--no-dev", "--no-hashes", "--format", "requirements-txt"], cwd=ROOT, capture_output=True, text=True, encoding="utf8", check=True).stdout
    out = []
    for line in req.splitlines():
        m = re.match(r"^([A-Za-z0-9_.-]+)==([^\s;]+)", line)
        if not m:
            continue
        try:
            d = metadata.distribution(m.group(1))
        except metadata.PackageNotFoundError:
            continue
        md = d.metadata
        lic = md.get("License-Expression") or ""
        if not lic:
            cl = [c.split("::")[-1].strip() for c in md.get_all("Classifier") or [] if c.startswith("License ::")]
            lic = " / ".join(cl) or (md.get("License") or "")[:80]
        out.append((md["Name"], d.version, " ".join(lic.split())[:90]))
    return sorted(out, key=lambda x: x[0].lower())


def web_deps() -> list[tuple[str, str, str]]:
    raw = subprocess.run("pnpm licenses list --prod --json", cwd=WEB, capture_output=True, text=True, encoding="utf8", shell=True, check=True).stdout
    out = []
    for lic, pkgs in json.loads(raw).items():
        for p in pkgs:
            for v in p.get("versions", [""]):
                out.append((p["name"], v, lic))
    return sorted(out, key=lambda x: x[0].lower())


def rust_deps() -> tuple[list[tuple[str, str, str]], dict]:
    meta = json.loads(subprocess.run(["cargo", "metadata", "--format-version", "1", "--locked"], cwd=TAURI, capture_output=True, text=True, encoding="utf8", check=True).stdout)
    root_id = meta["resolve"]["root"]
    reachable: set[str] = set()
    nodes = {n["id"]: n for n in meta["resolve"]["nodes"]}
    stack = [root_id]
    while stack:
        i = stack.pop()
        if i in reachable:
            continue
        reachable.add(i)
        for d in nodes[i]["deps"]:
            if any(k["kind"] in (None, "build") for k in d["dep_kinds"]):
                stack.append(d["pkg"])
    pk = [p for p in meta["packages"] if p["id"] in reachable and p["id"] != root_id]
    rows = sorted(((p["name"], p["version"], p.get("license") or "") for p in pk), key=lambda x: x[0])
    sbom = {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
            "metadata": {"component": {"type": "application", "name": "osintcc-desktop", "version": "0.1.0"}},
            "components": [{"type": "library", "name": n, "version": v, "purl": f"pkg:cargo/{n}@{v}",
                            "licenses": [{"expression": lic}] if lic else []} for n, v, lic in rows]}
    return rows, sbom


def section(title: str, rows: list[tuple[str, str, str]]) -> tuple[str, Counter, list]:
    c: Counter = Counter()
    flagged = []
    for n, v, lic in rows:
        k = classify(lic)
        c[k] += 1
        if k != "permissive":
            flagged.append((n, v, lic, k))
    md = [f"## {title}", "", f"{len(rows)} packages. " + ", ".join(f"{k}: {n}" for k, n in c.most_common()), ""]
    if flagged:
        md += ["| Package | Version | Licence | Classification |", "|---|---|---|---|"] + [f"| {n} | {v} | {lic or '(none declared)'} | {k} |" for n, v, lic, k in flagged] + [""]
    else:
        md += ["Every package is permissively licensed.", ""]
    return "\n".join(md), c, flagged


def main() -> int:
    py, web = python_deps(), web_deps()
    rs, sbom = rust_deps()
    (ROOT / "docs" / "supply-chain" / "sbom-rust.cdx.json").write_text(json.dumps(sbom, indent=1), encoding="utf8")
    parts, total_flagged = [], 0
    by_license: dict[str, int] = defaultdict(int)
    for title, rows in (("Python (runtime, bundled into the sidecar)", py), ("Web (runtime, bundled into the UI)", web), ("Rust crates (desktop shell, release build graph)", rs)):
        md, _, flagged = section(title, rows)
        parts.append(md)
        total_flagged += len(flagged)
        for _, _, lic in rows:
            by_license[lic or "(none)"] += 1
    head = ["# Licence audit", "", "Generated by `scripts/license_audit.py` from the lockfiles' installed metadata. It lists every runtime/build-graph dependency "
            "that ships and calls out anything that is not plainly permissive. **An inventory, not legal advice.**", "",
            f"Totals: {len(py)} Python, {len(web)} web, {len(rs)} Rust. Flagged for human review: **{total_flagged}**.", "",
            "MPL-2.0 packages (e.g. certifi) are counted as permissive here: it is file-level weak copyleft and they are redistributed unmodified.", "",
            "Build-time tools that do not ship in the artefacts (PyInstaller, Playwright, ruff, mypy, vitest, ...) are outside this inventory. "
            "PyInstaller is GPL-2.0-or-later *with a bootloader exception* that permits distributing the frozen output under any licence; "
            "that exception is the reason it was chosen, and it should be re-read before any commercial redistribution.", "",
            "Bundled third-party **tools** (Subfinder, Sherlock, Maigret, amass, theHarvester, ExifTool, Tesseract ...) are never redistributed: "
            "they are discovered on the user's machine and run as separate processes. See `docs/source-licenses.md`.", ""]
    (ROOT / "docs" / "license-audit.md").write_text("\n".join(head + parts), encoding="utf8")
    print(f"python={len(py)} web={len(web)} rust={len(rs)} flagged={total_flagged}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
