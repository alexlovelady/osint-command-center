"""OSINT Command Center plugin SDK (protocol v1). Standard library only: copy this file next to your entrypoint.

A plugin is a small program the host runs twice per target, in a separate process with a minimal environment:

    python entrypoint.py --phase plan    <  {"protocol":1,"phase":"plan","target":{...}}     ->  {"requests":[{"url":"https://..."}]}
    python entrypoint.py --phase parse   <  {"protocol":1,"phase":"parse","target":{...},"responses":[...]}  ->  result JSON

The plugin NEVER touches the network itself. It asks the host for URLs in the plan phase; the host checks them against the
domains the manifest declared, fetches them with SSRF protection and rate limits, and hands the responses back. In the parse
phase the plugin turns responses into findings. Everything it returns is validated; anything else is discarded.

    from osintcc_plugin_sdk import run, finding, artifact

    def plan(target):            # -> list of URLs (strings)
        return [f"https://{target['canonical']}/robots.txt"]

    def parse(target, responses):  # -> dict (see result())
        ...
    run(plan, parse)
"""
from __future__ import annotations

import base64
import json
import sys
from typing import Any, Callable

PROTOCOL = 1


def response_body(r: dict[str, Any]) -> bytes:
    return base64.b64decode(r.get("body_b64", ""))


def artifact(name: str, content: bytes, source_url: str | None = None, mime_type: str = "application/json", http_status: int | None = None) -> dict:
    return {"name": name, "content_b64": base64.b64encode(content).decode(), "mime_type": mime_type, "source_url": source_url, "http_status": http_status}


def finding(subject_type: str, subject_key: str, predicate: str, value: Any, confidence: str = "low", reason: str = "", artifact_index: int = 0) -> dict:
    return {"subject": {"type": subject_type, "key": subject_key, "display": subject_key}, "predicate": predicate, "value": value,
            "confidence": confidence, "confidence_reason": reason, "artifact_index": artifact_index}


def relationship(a: tuple[str, str], b: tuple[str, str], relation_type: str, confidence: str = "low", reason: str = "", artifact_index: int = 0) -> dict:
    return {"from_entity": {"type": a[0], "key": a[1], "display": a[1]}, "to_entity": {"type": b[0], "key": b[1], "display": b[1]},
            "relation_type": relation_type, "confidence": confidence, "confidence_reason": reason, "artifact_index": artifact_index}


def result(status: str = "success", artifacts: list[dict] | None = None, findings: list[dict] | None = None,
           relationships: list[dict] | None = None, warnings: list[str] | None = None, error_code: str | None = None) -> dict:
    return {"status": status, "artifacts": artifacts or [], "findings": findings or [], "relationships": relationships or [],
            "warnings": warnings or [], "error_code": error_code}


def run(plan: Callable[[dict], list[str]], parse: Callable[[dict, list[dict]], dict]) -> None:
    phase = sys.argv[sys.argv.index("--phase") + 1] if "--phase" in sys.argv else ""
    msg = json.loads(sys.stdin.read() or "{}")
    if msg.get("protocol") != PROTOCOL:
        print(json.dumps({"error": "unsupported protocol"}))
        sys.exit(2)
    if phase == "plan":
        print(json.dumps({"requests": [{"url": u} for u in plan(msg["target"])]}))
    elif phase == "parse":
        print(json.dumps(parse(msg["target"], msg.get("responses", []))))
    else:
        print(json.dumps({"error": "unknown phase"}))
        sys.exit(2)
