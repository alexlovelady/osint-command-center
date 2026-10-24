"""Command-line first-run setup:  python -m osintcc.setup [status | install [all|ids…] | model [id]] [--yes] [--data-dir DIR]

Same code path as the in-app Setup page. Nothing is downloaded without --yes (the plan with exact URLs is printed first).
"""
from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path
from typing import Any

from ..config import Settings
from . import installer


def _printer(ev: dict[str, Any]) -> None:
    if ev.get("phase") == "download" and ev.get("total"):
        print(f"\r  {ev.get('id', '')}: {ev['bytes'] / 1e6:7.1f} / {ev['total'] / 1e6:.1f} MB", end="", flush=True)
    elif ev.get("phase") == "model" and ev.get("total"):
        print(f"\r  {ev.get('status')}: {(ev.get('completed') or 0) / 1e9:5.2f} / {ev['total'] / 1e9:.2f} GB", end="", flush=True)
    else:
        print(f"\n  [{ev.get('phase')}] {ev.get('id', '') or ev.get('status', '')} {ev.get('message', '')}".rstrip(), flush=True)


async def amain(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="osintcc.setup")
    ap.add_argument("action", choices=["status", "install", "model"], nargs="?", default="status")
    ap.add_argument("what", nargs="*")
    ap.add_argument("--yes", action="store_true", help="confirm the downloads shown in the plan")
    ap.add_argument("--data-dir")
    ns = ap.parse_args(argv)
    s = Settings(data_dir=Path(ns.data_dir)) if ns.data_dir else Settings()
    st = await installer.status(s)
    if ns.action == "status":
        print(f"platform {st['platform']}, RAM {st['ram_gb']} GB, tools dir {st['tools_dir']}")
        for t in st["tools"]:
            state = f"installed ({'managed' if t['managed'] else 'on PATH'}) {t['path']}" if t["installed"] else (
                "not installed" if t["installable"] else f"unavailable: {t['reason']}")
            print(f"  {t['id']:<13} {t['version']:<9} {state}")
        m = st["recommended_model"]
        print(f"recommended model for this machine: {m['id']} ({m['download_gb']} GB, {m['label']})")
        return 0
    if ns.action == "install":
        ids = [t["id"] for t in st["tools"] if t["installable"] and not t["installed"] and t["id"] != "ollama"] if ns.what in ([], ["all"]) else ns.what
        plan = installer.plan(s, ids)
        print("Plan:")
        for p in plan:
            print(f"  {p['id']} {p['version']}: {', '.join(p['urls'])} {f"({p['size_mb']} MB)" if p['size_mb'] else ''}")
        if not ns.yes:
            print("\nNothing was downloaded. Re-run with --yes to proceed.")
            return 1
        rc = 0
        for p in plan:
            try:
                r = await installer.install(s, p["id"], progress=_printer)
                print(f"\n  {r['id']}: installed at {r['path']} — {r.get('reported_version') or 'version check failed'}")
            except installer.SetupError as exc:
                print(f"\n  {p['id']}: FAILED — {exc}")
                rc = 2
        return rc
    model = ns.what[0] if ns.what else st["recommended_model"]["id"]
    print(f"Model: {model} (pulled through your local Ollama from the Ollama registry; Ollama verifies each blob's digest)")
    if not ns.yes:
        print("Nothing was downloaded. Re-run with --yes to proceed.")
        return 1
    if not installer.ollama_path():
        print("Ollama is not installed; installing it first.")
        await installer.install(s, "ollama", progress=_printer)
    try:
        await installer.pull_model(model, _printer)
    except installer.SetupError as exc:
        print(f"\nFAILED — {exc}")
        return 2
    print(f"\nModel ready: {model}. Add it as an AI profile in the app (Settings → AI) or run the in-app Setup page to do it automatically.")
    return 0


def main() -> int:
    return asyncio.run(amain(sys.argv[1:]))


if __name__ == "__main__":
    raise SystemExit(main())
