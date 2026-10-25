"""Copilot tools for DARKINT. Summaries and explanations of stored, redacted events; one proposal that installs a DISABLED workflow draft.

Enforced here, not by the model:
  * nothing here queries a provider, runs a check, enables a monitor, widens a consent or fetches data: the tools read what is already stored;
  * only fields that were already redacted at ingest exist to be read (titles, categories, provider, dates): there is no stored secret or leaked record to reveal or invent;
  * every statement carries real evidence ids from this case, and a reported event is always called reported, never confirmed compromise;
  * with a cloud model only counts and generic text are shown.
"""
from __future__ import annotations

import re
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..darkint import service as dsvc
from ..db.models import CaseMember, Evidence, ExposureEvent, ExposureMonitorConfig, ExposureReview, Subject
from ..profile import consent, hooks
from .profile_tools import Refused

READ_TOOLS = ("darkint_summary", "explain_exposure_event")
ACTION_TOOLS = ("propose_darkint_workflow",)
ROLE_RANK = {"viewer": 1, "editor": 2, "owner": 3}
INTENTS = {"darkint_summary": "darkint_summary", "darkint_event": "explain_exposure_event"}
PATTERNS = [
    ("darkint_event", re.compile(r"explain (this|the) (exposure|breach|leak|ransomware|dark ?web)( event| report| listing| incident)?|what does (this|the) (breach|leak|listing) mean", re.IGNORECASE)),
    ("darkint_summary", re.compile(r"dark ?web|ransomware|breach(es)? (coverage|summary|status)|exposure coverage|which (providers|sources) .{0,30}(checked|asked)|have (we|i) checked (for )?(breach|leak)|reported (breach|leak|exposure)", re.IGNORECASE)),
]
NOT_VERIFIED = ("A reported event is what a provider or source says. It is not proof that data leaked, that it is accurate, or that it is still reachable, and I cannot see any leaked content: "
                "none is stored here.")


def _role(db: Session, user: str, case_id: str) -> str:
    m = db.get(CaseMember, (case_id, user))
    if not m:
        raise Refused("case not found or you do not have the needed role on it")
    return m.access_role


def _need(role: str, what: str) -> None:
    if ROLE_RANK[role] < ROLE_RANK["editor"]:
        raise Refused(f"{what} needs the editor or owner role on this case")


def _subject(db: Session, case_id: str, args: dict[str, Any]) -> Subject:
    sid = args.get("subject_id")
    s = db.get(Subject, str(sid)) if sid else db.scalars(select(Subject).where(Subject.case_id == case_id, Subject.status == "active").order_by(Subject.created_at)).first()
    if s is None or s.case_id != case_id or s.status == "purged":
        raise Refused("this case has no target profile to summarise")
    return s


def _citations(db: Session, ids: list[str]) -> list[dict[str, str]]:
    out = []
    for i in dict.fromkeys(ids):
        e = db.get(Evidence, i)
        if e:
            out.append({"id": e.id, "title": e.title or e.kind, "sha256": e.sha256[:16]})
    return out


def read(db: Session, st: Any, user: str, case_id: str, name: str, args: dict[str, Any]) -> dict[str, Any]:
    role = _role(db, user, case_id)
    _need(role, "exposure details")
    s = _subject(db, case_id, args)
    if name == "darkint_summary":
        cov = dsvc.coverage(db, st, s)
        groups = dsvc.grouped_events(db, s)
        unreviewed = sum(1 for g in groups if g["review_status"] == "unreviewed")
        ev_ids = [e["evidence_id"] for g in groups for e in g["events"] if e["evidence_id"]]
        return {"subject": s.display_name, "coverage": [{"identifier": c["identifier"], "kind": c["kind"], "state": c["label"], "meaning": c["meaning"],
                                                         "providers": [{"provider": p["provider"], "state": dsvc.STATE_LABEL[p["state"]], "checked_at": p["checked_at"]} for p in c["providers"]]} for c in cov["items"]],
                "incidents": [{"sources": g["sources"], "categories": g["categories"], "first_seen": g["first_seen"], "review": g["review_status"], "corroborated": g["corroborated"],
                               "events": [{"id": e["id"], "title": e["title"], "provider": e["provider"], "claim": e["claim_label"], "evidence_id": e["evidence_id"]} for e in g["events"]]} for g in groups],
                "unreviewed_incidents": unreviewed, "caveat": NOT_VERIFIED, "notice": cov["notice"], "citations": _citations(db, ev_ids)}
    if name == "explain_exposure_event":
        e = db.get(ExposureEvent, str(args.get("event_id") or ""))
        if e is None:
            rows = [x for x in db.scalars(select(ExposureEvent).where(ExposureEvent.case_id == case_id, ExposureEvent.subject_id == s.id).order_by(ExposureEvent.created_at.desc()))
                    if not db.scalars(select(ExposureReview).where(ExposureReview.event_id == x.id)).first()][:1]
            e = rows[0] if rows else None
        if e is None or e.case_id != case_id:
            raise Refused("there is no unreviewed exposure event to explain")
        d = dsvc.event_dict(e)
        return {"event": {k: d[k] for k in ("id", "title", "provider", "event_type", "categories", "first_seen", "claim_label", "confidence", "caveat", "evidence_id")},
                "meaning": {"breach": "A provider lists a breach that included this kind of identifier. Whether this person's record was in it, and what it contained, is not shown here.",
                            "ransomware_listing": "A ransomware group claimed this organization on a leak site. The claim is the actor's and is not independent proof of compromise.",
                            "paste": "A paste or public post was reported to mention the identifier. It may be old, incomplete or unrelated.",
                            "advisory": "An imported advisory or intelligence item mentioned it. Check its TLP and source before acting."}.get(e.event_type, "A source reported this."),
                "suggested_actions": [{"action": a, "what": dsvc.ACTION_TEXT[a][0]} for a in dsvc.suggest_actions(e)], "caveat": NOT_VERIFIED,
                "citations": _citations(db, [e.evidence_id] if e.evidence_id else [])}
    raise Refused(f"'{name}' is not an exposure tool")


def cloud_view(name: str, r: dict[str, Any]) -> dict[str, Any]:
    notice = "Exposure details are withheld from cloud models; only counts and generic text are shown."
    if name == "darkint_summary":
        states: dict[str, int] = {}
        for c in r["coverage"]:
            states[c["state"]] = states.get(c["state"], 0) + 1
        return {"coverage_states": states, "incident_count": len(r["incidents"]), "unreviewed_incidents": r["unreviewed_incidents"], "caveat": r["caveat"], "notice": notice}
    return {"suggested_actions": [a["action"] for a in r["suggested_actions"]], "caveat": r["caveat"], "notice": notice}


def md_summary(r: dict[str, Any]) -> str:
    out = [f"**Exposure coverage for {r['subject']}**", ""]
    for c in r["coverage"]:
        out.append(f"- `{c['identifier']}` ({c['kind']}): **{c['state']}**. {c['meaning']}")
        out += [f"  - {p['provider']}: {p['state']}" + (f" (checked {p['checked_at']})" if p["checked_at"] else "") for p in c["providers"]]
    if not r["coverage"]:
        out.append("- No identifiers that providers can check have been added.")
    out += ["", f"**Reported incidents** ({len(r['incidents'])}; {r['unreviewed_incidents']} not yet reviewed)"]
    for g in r["incidents"]:
        out.append(f"- {', '.join(g['categories']) or 'category not stated'} via {', '.join(g['sources'])}; review: {g['review']}" + ("; reported by more than one source" if g["corroborated"] else ""))
        out += [f"  - {e['title']} ({e['provider']}; {e['claim']})" + (f" (evidence `{e['evidence_id'][:8]}`)" if e["evidence_id"] else "") for e in g["events"]]
    if not r["incidents"]:
        out.append("- Nothing has been reported by the sources that were checked.")
    out += ["", f"_{r['notice']}_", f"_{r['caveat']}_"]
    return "\n".join(out)


def md_event(r: dict[str, Any]) -> str:
    e = r["event"]
    out = [f"**{e['title']}** ({e['provider']}, {e['event_type'].replace('_', ' ')})", "", f"- Status: {e['claim_label']}; confidence {e['confidence']}.", f"- Data categories: {', '.join(e['categories']) or 'not stated'}.",
           f"- {r['meaning']}", "", "**Practical next steps**"] + [f"- {a['what']}" for a in r["suggested_actions"]] + ["", f"_{r['caveat']}_"]
    return "\n".join(out)


RENDERERS = {"darkint_summary": md_summary, "explain_exposure_event": md_event}


def propose(db: Session, st: Any, user: str, case_id: str, args: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    role = _role(db, user, case_id)
    _need(role, "proposing an exposure workflow")
    s = _subject(db, case_id, args)
    from ..automations import catalog
    t = catalog.get(str(args.get("slug") or "").strip().lower())
    if not t or t["category"] != "Exposure":
        raise Refused("name one of the exposure templates (DARK-01 to DARK-05)")
    inputs = args.get("inputs") or {}
    if not isinstance(inputs, dict) or any(k not in t["definition"]["inputs"] for k in inputs):
        raise Refused(f"template {t['key']} accepts only: {', '.join(t['definition']['inputs']) or 'no inputs'}")
    mid = inputs.get("monitor_id")
    prov_names: list[str] = []
    if mid is not None:
        m = db.get(ExposureMonitorConfig, str(mid))
        if m is None or m.case_id != case_id or m.subject_id != s.id:
            raise Refused("that monitor does not belong to this subject; create one in the Exposure tab first")
        prov_names = list(m.providers_json)
    d = consent.check(db, s, "exposure_check")
    if not d.allowed:
        raise Refused(f"not proposed: this subject is not authorized for exposure checks ({d.reason})")
    clean = {"slug": t["slug"], "inputs": {k: v for k, v in inputs.items() if isinstance(v, str | int | float | bool | type(None))}, "subject_id": s.id}
    preview = {"template": f"{t['key']} {t['name']}", "will_contact": prov_names or "nothing until a monitor is bound", "capability_gaps": t["capability_gaps"],
               "installs": "a DISABLED draft bound to this subject; running or scheduling it later needs approval, activation and a live authorization. Revoking the consent switches it off."}
    return clean, preview


def execute(db: Session, st: Any, user: str, case_id: str, a: dict[str, Any]) -> dict[str, Any]:
    role = _role(db, user, case_id)
    _need(role, "installing an exposure workflow")
    s = _subject(db, case_id, {"subject_id": a.get("subject_id")})
    from ..db.models import Case
    case = db.get(Case, case_id)
    assert case is not None
    try:
        wf = hooks.install_template(db, s, case, a["slug"], a.get("inputs") or {}, user)
    except hooks.InstallError as exc:
        raise Refused(str(exc)) from exc
    return {"executed": True, "workflow_id": wf.id, "state": wf.state, "note": "Installed as a disabled draft bound to this subject. Open Automations to review, dry-run and request approval."}
