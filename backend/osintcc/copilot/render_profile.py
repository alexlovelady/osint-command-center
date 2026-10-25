"""Deterministic Markdown for the Target Profile tools. These answers need no model: they are computed from stored records and cite real evidence ids."""
from __future__ import annotations

import re
from typing import Any

from ..profile.registry import SOURCES

PROFILE_INTENTS: dict[str, str] = {
    "profile_known": "summarize_profile", "profile_exposed": "explain_exposure", "profile_next": "recommend_research_plan",
    "why_not_searched": "why_not_searched", "verify_queue": "create_verification_queue", "explain_image": "explain_image_match",
}
PROFILE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("profile_known", re.compile(r"what do (we|i) actually know|which (profiles|accounts) (have|did) i verified|what.s (been )?verified|what is verified|verified (profiles|accounts|information)|summari[sz]e (the |this )?(target|profile|subject)", re.IGNORECASE)),
    ("profile_exposed", re.compile(r"information is (publicly )?exposed|publicly exposed|exposure (summary|status)|am i exposed", re.IGNORECASE)),
    ("profile_next", re.compile(r"what should i (check|research|search) next|which (source|check|method)s? (should|to) (i )?(run|check|try)|research plan|what.s (not|un)covered", re.IGNORECASE)),
    ("why_not_searched", re.compile(r"why (wasn.t|weren.t|didn.t|haven.t|hasn.t).{0,60}(search|check|run|queried)|why (is|was) .{0,30} not (searched|checked)", re.IGNORECASE)),
    ("verify_queue", re.compile(r"verification queue|(cluster|group).{0,20}(lead|account)", re.IGNORECASE)),
    ("explain_image", re.compile(r"explain this image match|image match", re.IGNORECASE)),
]


def detect_profile_intent(text: str) -> str | None:
    return next((n for n, rx in PROFILE_PATTERNS if rx.search(text)), None)


def mentioned_source(text: str) -> str:
    low = text.casefold()
    for s in SOURCES.values():
        if re.search(r"\b" + re.escape(s.id.replace("_", " ")) + r"\b", low.replace("_", " ")) or s.label.casefold() in low:
            return s.id
    return ""


def _cite(rows: list[dict[str, Any]]) -> str:
    return " ".join(f"(evidence `{e['id'][:8]}`, sha256 `{e['sha256'][:12]}`)" for e in rows) if rows else "(no evidence attached)"


def md_profile_summary(r: dict[str, Any]) -> str:
    s = r["subject"]
    out = [f"**What is actually known about {s['label']}** ({s['mode']} mode; authorization: {r['authorization']})", ""]
    out.append("**Verified, with evidence**")
    out += [f"- {v['field'].replace('_', ' ')}: {v['text']} — {v['state']}; {_cite(v['evidence'])}" for v in r["verified"]] or ["- Nothing has been verified yet."]
    if r["confirmed_accounts"]:
        out += ["", "**Accounts confirmed by a person**"] + [f"- {a['url']} {_cite(a['evidence'])}" for a in r["confirmed_accounts"]]
    out += ["", f"**Leads, not facts** ({len(r['unverified_leads'])}) — unverified; a matching handle is not the same person"]
    out += [f"- {x['url']} — seen by {', '.join(x['tools'])}, {x['independent_signals']} independent signal(s); {_cite(x['evidence'])}" for x in r["unverified_leads"][:12]] or ["- None."]
    if r["contradictions"]:
        out += ["", "**Contradicting information (shown side by side, not resolved)**"]
        for c in r["contradictions"]:
            out.append(f"- {c['field'].replace('_', ' ')}: " + " vs ".join(f"“{v['text']}” ({v['state']})" for v in c["values"]))
    if r["not_assessed_sections"]:
        out += ["", "**Not assessed** (this is not proof the information does not exist): " + ", ".join(r["not_assessed_sections"])]
    if r["exposure"] is not None:
        e = r["exposure"]
        out += ["", f"**Exposure**: {e['confirmed_exposure']} confirmed, {e['not_found_in_checked_sources']} not found in checked sources, {e['not_assessed']} not assessed."]
    c = r["coverage"]
    out += ["", f"**Research coverage**: {c['completed']} of {c['approved']} approved task(s) completed. {c['label']}", "", f"_{r['caveat']}_"]
    return "\n".join(out)


def md_research_plan(r: dict[str, Any]) -> str:
    out = ["**Suggested research, in priority order** (only what policy and authorization currently allow):", ""]
    for x in r["recommended"]:
        out.append(f"{x['rank']}. **{x['name']}** — {x['why']} Maturity: {x['maturity']}." + (" Needs your explicit confirmation." if x["needs_confirmation"] else ""))
    if not r["recommended"]:
        out.append("Nothing eligible is left to run. Add an input or renew authorization to continue.")
    if r["manual_methods"]:
        out += ["", "**Manual methods not yet used**:"] + [f"- {m['name']}: {m['why']}" for m in r["manual_methods"]]
    if r["not_recommended"]:
        out += ["", "**Not recommended right now, and why**:"] + [f"- {b['name']}: {b['reason']}" for b in r["not_recommended"]]
    out += ["", r["note"]]
    return "\n".join(out)


def md_verification_queue(r: dict[str, Any]) -> str:
    out = [f"**{r['total_leads']} unresolved lead(s), grouped for review**", ""]
    for c in r["clusters"]:
        out.append(f"- **{c['site_family']}** ({c['count']}): {', '.join(c['urls'][:4])}{' …' if c['count'] > 4 else ''} — seen by {', '.join(c['tools'])}")
    if not r["clusters"]:
        out.append("No unresolved leads.")
    out += ["", r["note"]]
    return "\n".join(out)


def md_exposure(r: dict[str, Any]) -> str:
    out = ["**Exposure indicators**", ""]
    for i in r["indicators"]:
        out.append(f"- **{i['class']}**: {i['result']}" + (f", risk {i['risk']}" if i["result"] == "confirmed exposure" else "") + (f" ({i['date'][:10]})" if i["date"] else "") + f". {i['meaning']}")
        if i["descriptor"]:
            out.append(f"  - {i['descriptor']}")
        out += [f"  - Do: {g}" for g in i["remediation"]]
    if not r["indicators"]:
        out.append("Nothing has been assessed. Absence of records means **not assessed**, not 'safe'.")
    out += ["", r["never_shown"]]
    return "\n".join(out)


def md_why_not(r: dict[str, Any]) -> str:
    return f"**Why {r['name']} has not been searched** (maturity: {r['maturity']})\n\n" + "\n".join(f"- {x}" for x in r["reasons"]) + f"\n\n_{r['legal_note']}_"


def md_image_matches(r: dict[str, Any]) -> str:
    out = ["**Image matches to review**", ""]
    for m in r["matches"]:
        out.append(f"- {m['type'].replace('_', ' ')} ({m['state']})" + (f", similarity {round(m['score'] * 100)}%" if m.get("score") is not None else "") + (f" at {m['matched_url']}" if m.get("matched_url") else ""))
    if not r["matches"]:
        out.append("No unreviewed matches.")
    out += ["", r["limits"], r["note"]]
    return "\n".join(out)


RENDERERS = {"summarize_profile": md_profile_summary, "recommend_research_plan": md_research_plan, "create_verification_queue": md_verification_queue,
             "explain_exposure": md_exposure, "why_not_searched": md_why_not, "explain_image_match": md_image_matches}


# Active Intelligence & Verification answers share the same deterministic path: computed from stored records, no model needed.
from . import aiv_tools as _aiv

PROFILE_INTENTS.update(_aiv.INTENTS)
PROFILE_PATTERNS[:0] = _aiv.PATTERNS
RENDERERS.update(_aiv.RENDERERS)
from . import darkint_tools as _dark

PROFILE_INTENTS.update(_dark.INTENTS)
PROFILE_PATTERNS[:0] = _dark.PATTERNS
RENDERERS.update(_dark.RENDERERS)
