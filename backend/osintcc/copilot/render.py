"""Intent detection and deterministic answers.

These produce correct, cited answers from application data with no model, and they supply the facts a model is asked to explain.
"""
from __future__ import annotations

import json
import re
from typing import Any

from .kb import Hit, KnowledgeBase

_I = re.IGNORECASE
INTENTS: list[tuple[str, re.Pattern[str]]] = [
    ("next_steps", re.compile(r"next step|what (should|do) (i|we) do next|what now|recommend|what.s next|where (do|should) i (go|start)|suggest.*(source|step|approach)", _I)),
    ("conflicts", re.compile(r"conflict|contradict|disagree|inconsisten|mismatch", _I)),
    ("timeline", re.compile(r"timeline|chronolog|in order of time|sequence of events", _I)),
    ("diagnose", re.compile(r"(why|how).{0,40}(fail|error|not work|broke|didn.t|doesn.t work|won.t|skipp)|\bfailed\b|troubleshoot|\bnot working\b|\bdiagnos", _I)),
    ("summary", re.compile(r"summari[sz]e|summary|overview of (this|the) case|what (do we|have we) (know|found)|where are we", _I)),
    ("confidence", re.compile(r"confidence|how (sure|certain|reliable)|why is (this|it) (low|high|medium)", _I)),
    ("tutorial", re.compile(r"walk me through|tutorial|guide me|show me how|step[- ]by[- ]step|teach me|how do i (create|make|start|run|import|generate|set ?up|back ?up)", _I)),
    ("evidence", re.compile(r"\bevidence\b|what do we have on|find(ings)? (about|on|for)|anything (on|about)|search (the )?case|what does the (data|case) say|who (is|owns)|which (sources|tools) (found|reported)", _I)),
    ("tools", re.compile(r"which tools?|what tools?|tool (status|health)|installed|is .{2,25} (installed|working|available)|alternative", _I)),
]
APP_QUESTION = re.compile(r"\b(does|do|can|could) (the |this )?(app|application|it|tool|copilot|software)\b|\bis there (a|an)\b|\bwhere (is|do|can)\b|\bhow (do|can) i\b|\bbutton\b|\bfeature\b|\bsetting\b|\btab\b|\bpage\b|\bsupport", _I)
ACTION_CLAIM = re.compile(
    r"\b(i|we)(?:'ve| have|'ll have)?\s+(?:just\s+|already\s+|now\s+|successfully\s+)?(started|launched|created|added|saved|generated|installed|deleted|removed|updated|submitted|sent|ran|executed|scanned|enabled|disabled|configured|imported|exported|applied|changed|verified|confirmed|merged|promoted|marked|linked|approved|rejected|attested)\b"
    r"|\b(has|have) been\s+(started|launched|created|added|saved|generated|installed|deleted|removed|updated|submitted|sent|run|executed|enabled|disabled|configured|imported|exported|verified|confirmed|merged|promoted|marked|linked|approved|rejected)\b"
    r"|\b(search|run|scan|report|note|workflow)\s+(is|was)\s+(now\s+)?(running|started|launched|created|complete|completed|done)\b", _I)


def detect_intent(text: str) -> str | None:
    for name, rx in INTENTS:
        if rx.search(text):
            return name
    return None


def claims_action(text: str) -> bool:
    return bool(ACTION_CLAIM.search(text))


def is_app_question(text: str) -> bool:
    return bool(APP_QUESTION.search(text))


def mentioned_tools(text: str, tools: dict[str, dict[str, Any]]) -> list[str]:
    low = text.lower()
    return [aid for aid, t in tools.items() if re.search(r"\b" + re.escape(aid) + r"\b", low) or re.search(r"\b" + re.escape(t["name"].lower()) + r"\b", low)]


# ------------------------------------------------------------------------------------------------------------ markdown
def md_next_steps(steps: list[dict[str, Any]]) -> str:
    if not steps:
        return "No recommendations: there is no open case to analyse."
    out = ["**Recommended next steps** (ranked; each is computed from this case's stored data):", ""]
    for s in steps:
        out.append(f"{s['rank']}. **{s['title']}** — {s['why']}")
    out.append("\nThese are rule-based from counts and statuses in the case, not predictions. Nothing has been run.")
    return "\n".join(out)


def md_conflicts(res: dict[str, Any]) -> str:
    conf = res.get("conflicts", [])
    if not conf:
        s = "No conflicting statements found among the findings I can see."
        if res.get("withheld_restricted"):
            s += f" ({res['withheld_restricted']} restricted item(s) were not examined.)"
        return s
    out = [f"**{len(conf)} place(s) where sources disagree** (shown side by side; I do not pick a winner):", ""]
    for c in conf:
        out.append(f"- **{c['entity']} · {c['predicate']}**")
        for side in c["sides"]:
            out.append(f"  - `{json.dumps(side['value'], default=str)[:100]}` — reported by {', '.join(side['adapters'])} (best confidence: {side['best_confidence']}); evidence {', '.join(e[:8] for e in side['evidence'])}")
    return "\n".join(out)


def md_timeline(res: dict[str, Any]) -> str:
    ev = res.get("events", [])
    if not ev:
        return "There are no findings to place on a timeline yet."
    out = ["**Timeline** (basis is 'published' when the source gave a time, otherwise 'observed' = when this app collected it):", ""]
    for e in ev:
        w = e["when"].strftime("%Y-%m-%d %H:%M UTC") if hasattr(e["when"], "strftime") else str(e["when"])
        out.append(f"- {w} ({e['basis']}) — {e['text']} · {e['adapter']}")
    return "\n".join(out)


def md_summary(f: dict[str, Any], corr: dict[str, Any] | None = None) -> str:
    c = f["counts"]
    out = [f"**{f['title']}** — {f['category']} case, {f['status']}.", f"Purpose: {f['purpose'] or '(none written)'}", "",
           f"Stored: {c['targets']} target(s), {c['findings']} finding(s), {c['entities']} entit(ies), {c['relationships']} relationship(s), {c['evidence']} evidence item(s), "
           f"{c['observations']} observation(s), {c['claims']} claim(s), {c['requirements']} requirement(s), {c['notes']} note(s), {c['reports']} report(s)."]
    if f["targets"]:
        out.append("Targets: " + ", ".join(f"{t['value']} ({t['type']})" for t in f["targets"][:8]))
    if f["recent_runs"]:
        r = f["recent_runs"][0]
        out.append(f"Latest run: {r['status']} with {', '.join(r['adapters'] or [])} ({(r['started_at'] or '')[:10]}).")
    if corr and corr["distinct_statements"]:
        out.append(f"Corroboration: {corr['multi_source']} of {corr['distinct_statements']} distinct statements are supported by more than one source.")
    if f["open_requirements"]:
        out.append("Open questions: " + "; ".join(q["question"][:80] for q in f["open_requirements"][:5]))
    return "\n".join(out)


def md_diagnosis(d: dict[str, Any]) -> str:
    if not d.get("found"):
        return d.get("message", "Not found.")
    if "tool" in d:
        t = d["tool"]
        out = [f"**{t['name']}** — status: **{t['status']}**" + (f" ({t['detail']})" if t.get("detail") else "") + f"; class: {t['class']}.", ""]
        if not d["causes"]:
            out.append("I found no current problem: its health check passes and its recent jobs have no errors." if d["healthy"] else "No specific cause recorded.")
        for c in d["causes"]:
            out.append(f"- **{c['code']}** — {c['evidence']}. {c['meaning']} **Fix:** {c['fix']}")
        if d["alternatives"]:
            out.append("\nAlternatives available now: " + ", ".join(f"{a['name']} ({a['id']})" for a in d["alternatives"]) + ".")
        return "\n".join(out)
    run = d["run"]
    out = [f"**Run {run['id'][:8]}** — {run['status']}.", ""]
    for j in d["jobs"]:
        line = f"- {j['adapter']}: {j['status']}" + (f" / {j['error_code']}" if j["error_code"] else "")
        out.append(line)
        for c in j.get("causes", []):
            out.append(f"  - {c['meaning']} **Fix:** {c['fix']}")
        if j.get("alternatives"):
            out.append("  - Try instead: " + ", ".join(a["name"] for a in j["alternatives"][:3]))
    return "\n".join(out)


def md_tools(res: dict[str, Any]) -> str:
    rows = res.get("tools", [])
    out = [f"**{len(rows)} registered tools** (status comes from each tool's own health check):", ""]
    for t in rows:
        out.append(f"- **{t['name']}** (`{t['id']}`) — {t['status']}; {t['class']}; targets: {', '.join(t['targets'])}")
    return "\n".join(out)


def md_docs(hits: list[Hit], kb: KnowledgeBase, limit: int = 3) -> str:
    if not kb.supported(hits):
        near = ", ".join(f"*{h.chunk.title}*" for h in hits[:3] if h.coverage >= 0.3)
        return ("That isn't in the documentation I have, so I can't say the application does it." + (f" The closest documented topics are: {near}." if near else "")
                + " Use the search box in the Copilot panel to browse the documentation.")
    out = []
    for h in hits[:limit]:
        c = h.chunk
        if c.kind == "tutorial":
            steps = "\n".join(f"{i}. {s['beginner']}" for i, s in enumerate(c.meta["steps"], 1))
            out.append(f"**{c.title}** (guided walkthrough available)\n{steps}")
        elif c.kind == "module":
            how = "\n".join(f"- {x}" for x in c.meta.get("how_to", []))
            out.append(f"**{c.title}** — {c.meta['summary']}" + (f"\n{how}" if how else "") + ("\n" + " ".join(c.meta.get("notes", [])) if c.meta.get("notes") else ""))
        elif c.kind == "error":
            out.append(f"**{c.title}** — {c.meta['meaning']} **Fix:** {c.meta['fix']}")
        else:
            out.append(f"**{c.title}** — {c.text[:700]}")
    return "\n\n".join(out)
