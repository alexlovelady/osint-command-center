"""Copilot tools for Associated Email Discovery and the cross-INT expansion plan. Explain, plan and propose; never decide.

Enforced here, not by the model:
  * nothing can confirm, reject, merge or promote an address: those tools do not exist, and `profile.emails.review/promote/merge` are never imported;
  * the only action is a proposal that, once a person approves the card, runs ONE bounded expansion pass of passive, authorized steps (the same `expansion.run` the screen uses);
  * every statement lists real evidence ids from this case; hypotheses (likely / possible) and rejected matches are kept apart from confirmed facts;
  * with a cloud model only counts and generic text are shown.
"""
from __future__ import annotations

import re
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db.models import AssociatedEmail, Case, CaseMember, Evidence, Subject
from ..profile import emails, expansion
from .profile_tools import Refused

READ_TOOLS = ("associated_emails_summary", "plan_cross_int")
ACTION_TOOLS = ("propose_expansion_run",)
ROLE_RANK = {"viewer": 1, "editor": 2, "owner": 3}
INTENTS = {"emails_known": "associated_emails_summary", "cross_int_plan": "plan_cross_int"}
PATTERNS = [
    ("cross_int_plan", re.compile(r"cross.?int|correlate .{0,40}(across|disciplines)|investigate .{0,60}(associated|public accounts)|next investigative steps|expansion plan|what (else )?(could|can|should) (we|i) (research|investigate)", re.IGNORECASE)),
    ("emails_known", re.compile(r"associated e-?mail|other e-?mail (addresses|accounts)|(which|what) e-?mails?|contact addresses|evidence.backed (contact )?(e-?mail|address)", re.IGNORECASE)),
]
CAVEAT = ("An address found in a source is a candidate, not a fact. Only addresses a person confirmed are facts; likely and possible ones are hypotheses and rejected ones are matches a person ruled out.")


def _role(db: Session, user: str, case_id: str) -> str:
    m = db.get(CaseMember, (case_id, user))
    if not m:
        raise Refused("case not found or you do not have the needed role on it")
    return m.access_role


def _subject(db: Session, case_id: str, args: dict[str, Any]) -> Subject:
    sid = args.get("subject_id")
    s = db.get(Subject, str(sid)) if sid else db.scalars(select(Subject).where(Subject.case_id == case_id, Subject.status == "active").order_by(Subject.created_at)).first()
    if s is None or s.case_id != case_id or s.status == "purged":
        raise Refused("this case has no target profile yet; create one on the Target profile screen first")
    return s


def _cites(db: Session, ids: list[str]) -> list[dict[str, str]]:
    out = []
    for i in dict.fromkeys(ids):
        e = db.get(Evidence, i)
        if e:
            out.append({"id": e.id, "title": e.title or e.kind, "sha256": e.sha256[:16]})
    return out


def read(db: Session, st: Any, user: str, case_id: str, name: str, args: dict[str, Any]) -> dict[str, Any]:
    role = _role(db, user, case_id)
    if ROLE_RANK[role] < ROLE_RANK["editor"]:
        raise Refused("associated addresses need the editor or owner role on this case")
    s = _subject(db, case_id, args)
    if name == "associated_emails_summary":
        rows = list(db.scalars(select(AssociatedEmail).where(AssociatedEmail.subject_id == s.id).order_by(AssociatedEmail.discovered_at)))
        full = emails.list_for(db, st, s, role=role)["items"]
        by_id = {i["id"]: i for i in full}

        def card(r: AssociatedEmail) -> dict[str, Any]:
            d = by_id[r.id]
            return {"id": r.id, "address": d["address"], "classification": d["label"], "why": d["explanation"], "conflicts": [c["detail"] for c in d["conflicts"]], "state": r.state,
                    "sources": [{"kind": x["kind"], "group": x["group"], "explicit": x["explicit"], "evidence_id": x["evidence_id"], "basis": x["basis"]} for x in d["sources"]],
                    "exposure": d["exposure"]["label"], "decided_by": r.reviewed_by}
        verified = [card(r) for r in rows if r.state == "confirmed"]
        hypotheses = [card(r) for r in rows if r.state == "candidate"]
        rejected = [card(r) for r in rows if r.state == "rejected"]
        gaps = []
        case = db.get(Case, case_id)
        assert case is not None
        kinds = {i["kind"] for i in expansion.seeds(db, s)["inputs"]}
        if "username" not in kinds:
            gaps.append("No username input, so GitHub and username checks cannot look for developer-profile addresses.")
        if "url" not in kinds:
            gaps.append("No page input: add a confirmed profile or business contact page to read its published addresses.")
        gaps += [f"{h['address']} is Likely but not confirmed: confirm or reject it before anything is researched from it." for h in hypotheses if h["classification"] == "Likely"]
        ev = [x["evidence_id"] for c in (verified + hypotheses + rejected) for x in c["sources"] if x["evidence_id"]]
        return {"subject": s.display_name, "verified": verified, "hypotheses": hypotheses, "rejected": rejected, "gaps": gaps, "caveat": CAVEAT, "citations": _cites(db, ev)}
    if name == "plan_cross_int":
        case = db.get(Case, case_id)
        assert case is not None
        p = expansion.plan(db, s, case, st.adapters, st.settings)
        top = [x for x in p["steps"] if x["executable_now"]][:8]
        return {"subject": s.display_name, "stop_reason": p["stop_reason"], "budget": p["budget"], "policy": p["policy"],
                "next": [{"key": x["key"], "module": x["module"], "source": x["source"], "on": x["identifier"], "depth": x["depth"], "why": x["origin_path"][-1] if x["origin_path"] else "", "priority": x["priority"]} for x in top],
                "needs_a_person": [{"module": x["module"], "source": x["source"], "on": x["identifier"], "needs": x["needs"], "reason": x["reason"]}
                                   for x in p["steps"] if x["needs"] in ("confirmation", "explicit_approval")][:10],
                "blocked": [{"source": x["source"], "on": x["identifier"], "reason": x["reason"]} for x in p["steps"] if x["needs"] in ("blocked", "depth_limit")][:10],
                "proposals": [{"address": x["label"], "state": x["state"], "action": x["action"], "reason": x["reason"]} for x in p["seeds"]["proposals"]],
                "skipped": p["seeds"]["skipped"], "rules": p["rules"], "caveat": CAVEAT, "citations": []}
    raise Refused(f"'{name}' is not an email tool")


def cloud_view(name: str, r: dict[str, Any]) -> dict[str, Any]:
    notice = "Address details are withheld from cloud models; only counts and generic text are shown."
    if name == "associated_emails_summary":
        return {"confirmed": len(r["verified"]), "hypotheses": len(r["hypotheses"]), "rejected": len(r["rejected"]), "gap_count": len(r["gaps"]), "caveat": r["caveat"], "notice": notice}
    return {"executable_steps": len(r["next"]), "needs_a_person": len(r["needs_a_person"]), "blocked": len(r["blocked"]), "stop_reason": r["stop_reason"], "caveat": r["caveat"], "notice": notice}


def md_summary(r: dict[str, Any]) -> str:
    out = [f"**Associated email addresses for {r['subject']}**", ""]

    def block(title: str, items: list[dict[str, Any]], empty: str) -> None:
        out.append(f"**{title}** ({len(items)})")
        for c in items:
            ev = ", ".join(f"`{x['evidence_id'][:8]}`" for x in c["sources"] if x["evidence_id"])
            out.append(f"- `{c['address']}`: **{c['classification']}**. {' '.join(c['why'])}" + (f" Evidence {ev}." if ev else ""))
        if not items:
            out.append(f"- {empty}")
        out.append("")
    block("Confirmed by a person", r["verified"], "None yet.")
    block("Hypotheses (not facts)", r["hypotheses"], "None.")
    block("Rejected matches", r["rejected"], "None.")
    out += ["**Gaps**"] + ([f"- {g}" for g in r["gaps"]] or ["- None noticed."]) + ["", f"_{r['caveat']}_"]
    return "\n".join(out)


def md_plan(r: dict[str, Any]) -> str:
    out = [f"**Cross-INT plan for {r['subject']}**", "", f"Budget: {r['budget']['used']} of {r['budget']['max_runs']} source runs used; depth limit {r['policy']['max_depth']}."
           + (f" Stopped: {r['stop_reason'].replace('_', ' ')}." if r["stop_reason"] else ""), "", "**Ready to run (passive, authorized)**"]
    out += [f"- {n['source']} on {n['on']} (depth {n['depth']}; priority {n['priority']}). {n['why']}" for n in r["next"]] or ["- Nothing is ready."]
    out += ["", "**Needs a person first**"] + ([f"- {n['module']}: {n['source']} on {n['on']} needs {n['needs'].replace('_', ' ')}. {n['reason']}" for n in r["needs_a_person"]] or ["- Nothing."])
    out += ["", "**Candidates (no research is planned from these until confirmed)**"] + ([f"- {p['address']}: {p['state']}. {p['reason']}" for p in r["proposals"]] or ["- None."])
    out += ["", "**Blocked**"] + ([f"- {b['source']} on {b['on']}: {b['reason']}" for b in r["blocked"]] or ["- None."])
    out += ["", f"_{r['caveat']}_"]
    return "\n".join(out)


RENDERERS = {"associated_emails_summary": md_summary, "plan_cross_int": md_plan}


def propose(db: Session, st: Any, user: str, case_id: str, args: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    role = _role(db, user, case_id)
    if ROLE_RANK[role] < ROLE_RANK["editor"]:
        raise Refused("proposing research needs the editor or owner role on this case")
    s = _subject(db, case_id, args)
    case = db.get(Case, case_id)
    assert case is not None
    p = expansion.plan(db, s, case, st.adapters, st.settings)
    if p["stop_reason"] in ("authorization", "case_not_open", "offline", "budget_exhausted"):
        raise Refused(f"not proposed: the expansion is stopped ({p['stop_reason'].replace('_', ' ')})")
    by_key = {x["key"]: x for x in p["steps"]}
    wanted = args.get("keys")
    if wanted is not None and (not isinstance(wanted, list) or not all(isinstance(k, str) for k in wanted)):
        raise Refused("keys must be a list of plan step keys")
    keys = list(wanted) if wanted else [x["key"] for x in p["steps"] if x["executable_now"] or x["needs"] == "confirmation"][: p["policy"]["max_per_pass"]]
    bad = [k for k in keys if k not in by_key or by_key[k]["needs"] in ("blocked", "already_done", "depth_limit", "explicit_approval")]
    if bad or not keys:
        raise Refused("not proposed: " + ("a named step is not available in the plan" if bad else "the plan has nothing ready to run"))
    keys = keys[: max(0, min(p["policy"]["max_per_pass"], p["budget"]["remaining"]))]
    steps = [by_key[k] for k in keys]
    return {"keys": keys, "subject_id": s.id}, {"steps": [{"source": x["source"], "on": x["identifier"], "depth": x["depth"], "contacts": x["endpoints"], "needs_confirmation": x["needs"] == "confirmation"} for x in steps],
                                                "budget": p["budget"], "note": "Runs passive, authorized steps only, once. Likely and possible addresses are not researched; exposure checks and active verification are never started from here.",
                                                "needs_confirmation": sorted({x["source_id"] for x in steps if x["needs"] == "confirmation"})}
