"""Local-only adapters: pure computation, zero network."""
from __future__ import annotations

import json

from ..base import (
    AdapterContext,
    AdapterManifest,
    AdapterResult,
    EntityRef,
    FindingDraft,
    RawArtifact,
    Target,
)

_KEYBOARD = {"q": "wa", "w": "qes", "e": "wrd", "r": "etf", "t": "ryg", "y": "tuh", "u": "yij", "i": "uok", "o": "ipl",
             "p": "ol", "a": "qsz", "s": "awdx", "d": "serfc", "f": "drtgv", "g": "ftyhb", "h": "gyujn", "j": "huikm",
             "k": "jiol", "l": "kop", "z": "asx", "x": "zsdc", "c": "xdfv", "v": "cfgb", "b": "vghn", "n": "bhjm", "m": "njk"}
_HOMOGLYPH = {"o": ["0"], "l": ["1", "i"], "i": ["1", "l"], "e": ["3"], "a": ["4"], "s": ["5"], "m": ["rn"], "w": ["vv"],
              "d": ["cl"], "g": ["q"], "b": ["6"]}
_TLDS = ["com", "net", "org", "co", "io", "info", "biz", "app"]
MAX_CANDIDATES = 300


def generate_lookalikes(domain: str) -> dict[str, str]:
    """Candidate -> technique. Deterministic order, capped. These are *possible* typo/lookalike registrations only."""
    name, _, tld = domain.rpartition(".")
    out: dict[str, str] = {}

    def add(n: str, t: str, technique: str):
        c = f"{n}.{t}"
        if c != domain and n and not n.startswith("-") and not n.endswith("-") and c not in out:
            out[c] = technique
    for i in range(len(name)):
        add(name[:i] + name[i + 1:], tld, "omission")
        add(name[:i] + name[i] + name[i:], tld, "repetition")
        for k in _KEYBOARD.get(name[i], ""):
            add(name[:i] + k + name[i + 1:], tld, "adjacent-key replacement")
        for h in _HOMOGLYPH.get(name[i], []):
            add(name[:i] + h + name[i + 1:], tld, "homoglyph")
        if i < len(name) - 1 and name[i] != name[i + 1]:
            add(name[:i] + name[i + 1] + name[i] + name[i + 2:], tld, "transposition")
        if 0 < i:
            add(name[:i] + "-" + name[i:], tld, "hyphenation")
    for t in _TLDS:
        add(name, t, "tld swap")
    return dict(list(out.items())[:MAX_CANDIDATES])


class LookalikeAdapter:
    manifest = AdapterManifest(
        id="lookalike", default_selected=False, name="Lookalike domain candidates (offline)", version="1.0.0", supported_target_types=["domain"],
        operation_class="local_only", needs_network=False, timeout_seconds=10, license="in-house (inspired by dnstwist)",
        endpoints=[], description="Generates possible typo/homoglyph registrations from the name alone. Resolving them is a separate, "
                                  "explicit step; nothing here touches the network.")

    async def health(self) -> dict:
        return {"status": "healthy", "version": self.manifest.version, "detail": "local computation"}

    async def run(self, target: Target, ctx: AdapterContext) -> AdapterResult:
        cands = generate_lookalikes(target.canonical)
        art = RawArtifact(name=f"lookalikes-{target.canonical}.json", content=json.dumps(cands, indent=1, sort_keys=True).encode())
        subj = EntityRef(type="domain", key=target.canonical, display=target.canonical)
        f = [FindingDraft(subject=subj, predicate="lookalike.candidate_count", value=len(cands), confidence="high",
                          confidence_reason="Computed locally from the domain string")]
        f += [FindingDraft(subject=subj, predicate="lookalike.candidate", value={"domain": c, "technique": t}, confidence="unknown",
                           confidence_reason="A generated possibility; it may not be registered and is not evidence of abuse")
              for c, t in list(cands.items())[:50]]
        return AdapterResult(adapter_id="lookalike", status="success", artifacts=[art], findings=f,
                             warnings=["Candidates are hypotheticals. Registration/abuse must be checked separately."])
