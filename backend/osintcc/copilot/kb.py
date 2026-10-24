"""Knowledge base for the Copilot: modules, tutorials, glossary, error codes, synced docs and live tool descriptions, ranked with BM25.

Everything the assistant may say about the application comes from here (or from live state / case evidence). `search` returns scored
chunks; `supported` tells the caller whether anything relevant was found so it can answer "not documented" instead of guessing.
"""
from __future__ import annotations

import json
import math
import re
from collections import Counter
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

KB_DIR = Path(__file__).parent / "kb"
_WORD = re.compile(r"[a-z0-9][a-z0-9_.+-]*")
_STOP = frozenset(["a", "an", "and", "are", "as", "at", "be", "but", "by", "do", "does", "for", "from", "how", "i", "if", "in", "is", "it", "its", "me", "my", "of", "on", "or", "so", "that", "the", "this", "to", "was", "what", "when", "where", "which", "who", "why", "will", "with", "you", "your", "can", "should", "would", "could", "not", "no", "yes", "mean", "means", "meaning", "explain", "tell", "about", "use", "using", "do", "does", "did", "support", "supports", "walk", "through", "show", "please", "help", "guide"])


def _stem(w: str) -> str:
    """Light suffix folding so 'creating', 'created' and 'create' meet. Only for plain words of 5+ letters."""
    if len(w) < 5 or not w.isalpha():
        return w
    for suf in ("ing", "ed", "es", "s"):
        if w.endswith(suf) and len(w) - len(suf) >= 4:
            w = w[: -len(suf)]
            break
    if len(w) >= 4 and w[-1] == w[-2] and w[-1] not in "aeiouls":   # running -> runn -> run
        w = w[:-1]
    return w[:-1] if w.endswith("e") and len(w) > 4 else w


def tokens(text: str) -> list[str]:
    out: list[str] = []
    for w in _WORD.findall(text.lower()):
        w = w.strip(".-+")
        if not w or w in _STOP:
            continue
        out.append(w)
        if "_" in w or "-" in w:                    # also index the parts: "tool_manager" matches "tool"
            out.extend(p for p in re.split(r"[_-]", w) if p and p not in _STOP)
        st = _stem(w)
        if st != w:
            out.append(st)
    return out


@dataclass
class Chunk:
    id: str
    kind: str                 # module | tutorial | glossary | error | doc | tool
    title: str
    text: str
    source: str               # what to cite: "module:tab-search", "doc:troubleshooting.md#Setup"
    meta: dict[str, Any] = field(default_factory=dict)


@dataclass
class Hit:
    chunk: Chunk
    score: float
    coverage: float = 0.0     # share of the query's (idf-weighted) terms found in this chunk


class Index:
    def __init__(self, chunks: list[Chunk], k1: float = 1.4, b: float = 0.75) -> None:
        self.chunks, self.k1, self.b = chunks, k1, b
        self.tf: list[Counter[str]] = []
        for c in chunks:
            toks = tokens(c.title) * 3 + tokens(c.text) + tokens(" ".join(map(str, c.meta.get("keywords", [])))) * 2
            self.tf.append(Counter(toks))
        self.len = [sum(t.values()) or 1 for t in self.tf]
        self.avg = (sum(self.len) / len(self.len)) if self.len else 1.0
        df: Counter[str] = Counter()
        for t in self.tf:
            df.update(t.keys())
        n = len(chunks)
        self.idf = {w: math.log(1 + (n - d + 0.5) / (d + 0.5)) for w, d in df.items()}

    def search(self, query: str, k: int = 6, kinds: set[str] | None = None) -> list[Hit]:
        words = list(dict.fromkeys(w for w in _WORD.findall(query.lower()) if w.strip(".-+") and w.strip(".-+") not in _STOP))
        groups = [list(dict.fromkeys(tokens(w))) for w in words]
        groups = [g for g in groups if g]
        if not groups:
            return []
        top = max(self.idf.values(), default=1.0)
        # a word counts for coverage with the weight of its most informative variant; a word unknown to the whole KB counts as fully unmatched
        weight = [max((self.idf.get(v, 0.0) for v in g), default=0.0) or top for g in groups]
        total = sum(weight) or 1.0
        hits: list[Hit] = []
        for i, c in enumerate(self.chunks):
            if kinds and c.kind not in kinds:
                continue
            tf, ln, s, got = self.tf[i], self.len[i], 0.0, 0.0
            for g, wt in zip(groups, weight, strict=True):
                matched = False
                for v in g:
                    f = tf.get(v, 0)
                    if f:
                        matched = True
                        s += self.idf.get(v, 0.0) * f * (self.k1 + 1) / (f + self.k1 * (1 - self.b + self.b * ln / self.avg))
                if matched:
                    got += wt
            if s > 0:
                hits.append(Hit(c, s, got / total))
        hits.sort(key=lambda h: -h.score)
        return hits[:k]


def _load(name: str) -> Any:
    return json.loads((KB_DIR / name).read_text(encoding="utf8"))


def _doc_chunks() -> list[Chunk]:
    out: list[Chunk] = []
    d = KB_DIR / "docs"
    if not d.is_dir():
        return out
    for p in sorted(d.glob("*.md")):
        head = p.stem
        buf: list[str] = []
        def flush(h: str, lines: list[str], _p: Path = p) -> None:
            body = "\n".join(lines).strip()
            if len(body) < 20:
                return
            for j in range(0, len(body), 1800):     # split very long sections
                part = body[j:j + 1800]
                out.append(Chunk(f"doc:{_p.name}#{h}:{j}", "doc", f"{_p.stem}: {h}", part, f"doc:{_p.name}#{h}"))
        for line in p.read_text(encoding="utf8").splitlines():
            m = re.match(r"^#{1,3}\s+(.*)", line)
            if m:
                flush(head, buf)
                head, buf = m.group(1).strip(), []
            elif line.startswith("|") and not re.match(r"^\|[-\s|]+\|?$", line) and not line.lower().startswith("| symptom"):
                flush(head, buf)                    # one chunk per table row keeps troubleshooting precise
                buf = []
                cells = [c.strip() for c in line.strip("|").split("|")]
                flush(cells[0][:60] or head, [" -- ".join(cells)])
            else:
                buf.append(line)
        flush(head, buf)
    return out


@lru_cache(maxsize=1)
def static_chunks() -> tuple[Chunk, ...]:
    cs: list[Chunk] = []
    for m in _load("modules.json"):
        text = m["summary"] + " " + " ".join(m.get("how_to", [])) + " " + " ".join(m.get("notes", []))
        cs.append(Chunk(f"module:{m['id']}", "module", m["title"], text, f"module:{m['id']}",
                        {"keywords": m.get("keywords", []), "where": m.get("where", {}), "how_to": m.get("how_to", []), "notes": m.get("notes", []),
                         "summary": m["summary"], "related": m.get("related", []), "mkind": m.get("kind")}))
    for t in _load("tutorials.json"):
        text = t["summary"] + " " + " ".join(s["beginner"] for s in t["steps"])
        cs.append(Chunk(f"tutorial:{t['id']}", "tutorial", t["title"], text, f"tutorial:{t['id']}", {"steps": t["steps"], "module": t.get("module")}))
    for g in _load("glossary.json"):
        cs.append(Chunk(f"glossary:{g['term']}", "glossary", g["term"], g["definition"], f"glossary:{g['term']}", {"keywords": [g["term"]]}))
    for e in _load("errors.json"):
        cs.append(Chunk(f"error:{e['code']}", "error", e["code"], f"{e['meaning']} {e['fix']}", f"error:{e['code']}",
                        {"code": e["code"], "meaning": e["meaning"], "fix": e["fix"], "keywords": [e["code"]]}))
    cs.extend(_doc_chunks())
    return tuple(cs)


def tool_chunks(adapters: dict[str, Any], health: dict[str, dict] | None = None) -> list[Chunk]:
    """One chunk per registered adapter, from its own manifest (and live health if supplied). Never hand-written."""
    out = []
    for aid, a in sorted(adapters.items()):
        m = a.manifest
        h = (health or {}).get(aid, {})
        text = (f"{m.name} ({aid}). {m.description} Class: {m.operation_class}. Contacts: {', '.join(m.endpoints) or ('nothing external' if not m.needs_network else 'its provider')}. "
                f"Target types: {', '.join(m.supported_target_types)}. Disciplines: {', '.join(m.disciplines)}. "
                + (f"Needs API key '{m.api_key_name}'. " if m.api_key_name else "") + (f"Install hint: {m.install_hint}. " if m.install_hint else "")
                + (f"Health now: {h.get('status')}. {h.get('detail', '')}" if h else ""))
        out.append(Chunk(f"tool:{aid}", "tool", m.name, text, f"tool:{aid}",
                         {"keywords": [aid, m.name, *m.supported_target_types, *m.disciplines], "manifest": m.model_dump(), "health": h}))
    return out


class KnowledgeBase:
    def __init__(self, extra: list[Chunk] | None = None) -> None:
        self.chunks = list(static_chunks()) + list(extra or [])
        self.index = Index(self.chunks)
        self.by_id = {c.id: c for c in self.chunks}

    def search(self, query: str, k: int = 6, kinds: set[str] | None = None) -> list[Hit]:
        return self.index.search(query, k, kinds)

    def get(self, cid: str) -> Chunk | None:
        return self.by_id.get(cid)

    def supported(self, hits: list[Hit], floor: float = 2.0, coverage: float = 0.45) -> bool:
        """True if the best hit is strong enough AND covers most of the question's terms. Otherwise the assistant must say it is not documented."""
        return bool(hits) and hits[0].score >= floor and hits[0].coverage >= coverage

    def module_for(self, route: str, tab: str | None = None) -> Chunk | None:
        if route == "case" and tab:
            return self.by_id.get("module:tab-" + tab.lower().replace(" ", "-"))
        return self.by_id.get("module:" + route)
