"""The bundled template catalog (30 definitions) plus availability, export and import. Templates are data files with a checksum; instantiating one
always creates a DISABLED draft."""
from __future__ import annotations

import hashlib
import json
from functools import lru_cache
from pathlib import Path
from typing import Any

TEMPLATE_DIR = Path(__file__).parent / "templates"
MATURITY = ("definition", "fixture_tested", "runtime_tested", "real_adapter_tested")


@lru_cache(maxsize=1)
def load_all() -> tuple[dict[str, Any], ...]:
    out = []
    for p in sorted(TEMPLATE_DIR.glob("*.json")):
        raw = p.read_bytes()
        t = json.loads(raw)
        t["checksum"] = hashlib.sha256(raw).hexdigest()
        out.append(t)
    return tuple(out)


def get(slug_or_key: str) -> dict[str, Any] | None:
    k = slug_or_key.lower()
    return next((t for t in load_all() if t["slug"] == k or t["key"].lower() == k), None)


def availability(t: dict[str, Any], status: dict[str, str], adapters: dict[str, Any]) -> dict[str, Any]:
    """ready | setup_required | partial, with exactly what is missing. `status` maps adapter id -> health status."""
    missing = []
    for a in t["dependencies"]:
        s = status.get(a, "not_registered")
        if a not in adapters:
            missing.append({"adapter": a, "status": "not_registered", "setup": "this adapter is not registered in this installation"})
        elif s != "healthy":
            m = adapters[a].manifest
            how = {"not_installed": m.install_hint or "Install it from Setup.", "requires_key": f"Add the {m.api_key_name or a} API key in Setup -> API keys."}.get(s, f"status: {s}")
            missing.append({"adapter": a, "status": s, "setup": how})
    optional_missing = [a for a in t["optional_dependencies"] if status.get(a) != "healthy"]
    if missing:
        state = "setup_required"
    elif t["capability_gaps"]:
        state = "partial"
    else:
        state = "ready"
    return {"state": state, "missing": missing, "optional_missing": optional_missing, "gaps": t["capability_gaps"]}


def public(t: dict[str, Any], av: dict[str, Any] | None = None, detail: bool = False) -> dict[str, Any]:
    d = {k: t[k] for k in ("slug", "key", "version", "category", "name", "description", "catalog_trigger", "tags", "dependencies", "optional_dependencies", "quota_note",
                           "maturity", "checksum", "capability_gaps")}
    d["trigger"] = t["definition"]["trigger"]["type"]
    d["installed_disabled"] = True
    if av is not None:
        d["availability"] = av
    if detail:
        d |= {k: t[k] for k in ("inputs", "legal_notes", "example_output", "instructions", "definition")}
        d["fixture_inputs"] = t["fixture"].get("inputs", {})
    return d


# ---------------------------------------------------------------------------------------------------------------- export / import
def export_workflow(name: str, definition: dict[str, Any]) -> dict[str, Any]:
    body = {"format": "osintcc-automation/1", "name": name, "definition": definition}
    body["sha256"] = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return body


def verify_import(doc: Any) -> dict[str, Any]:
    """Returns the definition if the integrity hash matches; raises ValueError otherwise. The caller validates the schema and stores it DISABLED."""
    if not isinstance(doc, dict) or doc.get("format") != "osintcc-automation/1" or not isinstance(doc.get("definition"), dict):
        raise ValueError("not an OSINT Command Center automation export")
    claimed = doc.get("sha256")
    body = {k: v for k, v in doc.items() if k != "sha256"}
    actual = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    if claimed != actual:
        raise ValueError("the integrity hash does not match: the file was changed after export")
    return doc["definition"]
