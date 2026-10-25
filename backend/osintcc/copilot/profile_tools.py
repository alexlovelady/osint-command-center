"""Copilot tools for the Target Profile workstation. Deterministic and read-only except for two proposals that a person must approve.

Principles enforced here, not by the model:
  * nothing can verify, confirm, reject or merge anything: the tool list contains no such tool and `profile.candidates.review` / `profile.service.review_claim`
    are never imported by the Copilot;
  * every statement carries real evidence ids from this case, and candidates/leads are always labelled as unverified;
  * with a cloud model only counts and generic text are shown: identifiers, descriptors, coordinates and evidence titles never leave the machine.
"""
from __future__ import annotations

import re
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db.models import (
    CaseMember,
    Evidence,
    ExposureIndicator,
    ImageAsset,
    ImageMatch,
    ProfileClaim,
    ProfileReviewEvent,
    Subject,
)
from ..profile import candidates, consent, exposure, hooks, images, reports, research
from ..profile import registry as preg
from ..profile import service as pservice

AIV_READ_TOOLS = ("aiv_status", "explain_aiv_plan", "explain_aiv_observation")      # defined in aiv_tools (they need no subject)
AIV_ACTION_TOOLS = ("propose_aiv_plan",)
DARK_READ_TOOLS = ("darkint_summary", "explain_exposure_event")                     # defined in darkint_tools
DARK_ACTION_TOOLS = ("propose_darkint_workflow",)
EMAIL_READ_TOOLS = ("associated_emails_summary", "plan_cross_int")                  # defined in email_tools
EMAIL_ACTION_TOOLS = ("propose_expansion_run",)
READ_TOOLS = ("summarize_profile", "recommend_research_plan", "explain_claim", "create_verification_queue", "explain_exposure", "guide_image_search", "why_not_searched",
              "explain_image_match", *AIV_READ_TOOLS, *DARK_READ_TOOLS, *EMAIL_READ_TOOLS)
ACTION_TOOLS = ("propose_enrichment_workflow", "draft_subject_report", *AIV_ACTION_TOOLS, *DARK_ACTION_TOOLS, *EMAIL_ACTION_TOOLS)
ROLE_RANK = {"viewer": 1, "editor": 2, "owner": 3}
CAT_WEIGHT = {"username_footprint": 3, "domain_infrastructure": 3, "organization_filings": 2, "public_mentions": 1, "professional_history": 2, "published_documents": 2, "images": 2, "exposure": 3}
MATURITY_BONUS = {"live_tested": 2, "partially_verified": 1, "mocked_only": 0, "manual": 1}


class Refused(Exception):
    """Mapped to ToolRefused by the caller (kept separate to avoid a circular import)."""


def _role(db: Session, user: str, case_id: str) -> str:
    m = db.get(CaseMember, (case_id, user))
    if not m:
        raise Refused("case not found or you do not have the needed role on it")
    return m.access_role


def _subject(db: Session, case_id: str, args: dict[str, Any]) -> Subject:
    sid = args.get("subject_id")
    if sid is not None:
        s = db.get(Subject, str(sid))
        if not s or s.case_id != case_id:
            raise Refused("that subject is not part of this case")
    else:
        s = db.scalars(select(Subject).where(Subject.case_id == case_id).order_by(Subject.created_at)).first()
    if s is None:
        raise Refused("this case has no target profile yet; create one on the Target profile screen first")
    if s.status == "purged":
        raise Refused("this subject was purged; nothing remains to discuss")
    return s


def _need(role: str, need: str, what: str) -> None:
    if ROLE_RANK[role] < ROLE_RANK[need]:
        raise Refused(f"{what} needs the editor or owner role on this case")


def _ev(db: Session, ids: list[str]) -> list[dict[str, str]]:
    out = []
    for i in ids:
        e = db.get(Evidence, i)
        if e:
            out.append({"id": e.id, "title": e.title or e.kind, "sha256": e.sha256[:16]})
    return out


# ---------------------------------------------------------------------------------------------------------------------------- read tools
def read(db: Session, st: Any, user: str, case_id: str, name: str, args: dict[str, Any], tools: dict[str, dict[str, Any]]) -> dict[str, Any]:
    if name in AIV_READ_TOOLS:
        from . import aiv_tools
        return aiv_tools.read(db, st, user, case_id, name, args)
    if name in DARK_READ_TOOLS:
        from . import darkint_tools
        return darkint_tools.read(db, st, user, case_id, name, args)
    if name in EMAIL_READ_TOOLS:
        from . import email_tools
        return email_tools.read(db, st, user, case_id, name, args)
    role = _role(db, user, case_id)
    s = _subject(db, case_id, args)
    if name == "summarize_profile":
        return _summarize(db, s, role)
    if name == "recommend_research_plan":
        _need(role, "editor", "research planning")
        return _plan(db, st, s, case_id, tools)
    if name == "explain_claim":
        return _explain_claim(db, s, str(args.get("claim_id") or ""))
    if name == "create_verification_queue":
        _need(role, "editor", "the verification queue")
        return _queue(db, s)
    if name == "explain_exposure":
        _need(role, "editor", "exposure details")
        return _explain_exposure(db, s)
    if name == "guide_image_search":
        _need(role, "editor", "image search guidance")
        return _guide(db, s, str(args.get("image_id") or ""))
    if name == "why_not_searched":
        _need(role, "editor", "source planning")
        return _why_not(db, st, s, case_id, str(args.get("source") or args.get("source_id") or ""), tools)
    if name == "explain_image_match":
        _need(role, "editor", "image match details")
        return _image_match(db, s, str(args.get("match_id") or ""))
    raise Refused(f"'{name}' is not a profile tool")


def _text(v: Any) -> str:
    return str(v.get("text") or v.get("url") or v) if isinstance(v, dict) else str(v)


def _summarize(db: Session, s: Subject, role: str) -> dict[str, Any]:
    prof = pservice.build_profile(db, s, role=role)
    verified: list[dict[str, Any]] = []
    contradictions: list[dict[str, Any]] = []
    claims = list(db.scalars(select(ProfileClaim).where(ProfileClaim.subject_id == s.id)))
    for c in claims:
        if c.validation_state in ("verified", "subject_confirmed") and (c.sensitivity != "RESTRICTED" or role != "viewer"):
            verified.append({"field": c.field, "text": _text(c.structured_value), "state": pservice.LABELS[c.validation_state], "evidence": _ev(db, c.evidence_ids), "reviewer": c.reviewer})
    by_field: dict[str, list[ProfileClaim]] = {}
    for c in claims:
        by_field.setdefault(c.field, []).append(c)
    for field, rows in by_field.items():
        texts = {_text(r.structured_value).casefold() for r in rows if r.validation_state != "rejected"}
        conf = [r for r in rows if r.validation_state == "conflicting"]
        if len(texts) > 1 or conf:
            contradictions.append({"field": field, "values": [{"text": _text(r.structured_value), "state": pservice.LABELS[r.validation_state], "evidence": _ev(db, r.evidence_ids)} for r in rows]})
    confirmed: list[dict[str, Any]] = [{"url": k["canonical_url"], "evidence": [{"id": e["id"], "title": e["title"], "sha256": e["sha256"][:16]} for e in k["evidence"]]} for k in candidates.list_candidates(db, s, "confirmed")]
    leads: list[dict[str, Any]] = [{"url": k["canonical_url"], "state": k["state"], "tools": k["adapters"], "independent_signals": k["independent_signals"], "note": k["note"],
              "evidence": [{"id": e["id"], "title": e["title"], "sha256": e["sha256"][:16]} for e in k["evidence"]]} for k in prof["unresolved_leads"]]
    cov = research.coverage(db, s, {})
    exp: dict[str, int] | None = None
    if role != "viewer":
        counts = {"confirmed_exposure": 0, "not_found_in_checked_sources": 0, "not_assessed": 0}
        for x in db.scalars(select(ExposureIndicator).where(ExposureIndicator.subject_id == s.id)):
            counts[x.status] += 1
        exp = counts
    cites: dict[str, dict[str, str]] = {}
    for grp in (verified, confirmed, leads):
        for row in grp:
            for e in row["evidence"]:
                cites[e["id"]] = e
    for cd in contradictions:
        for v in cd["values"]:
            for e in v["evidence"]:
                cites[e["id"]] = e
    return {"subject": {"label": s.display_name, "mode": s.mode, "type": s.type}, "verified": verified, "confirmed_accounts": confirmed, "unverified_leads": leads,
            "contradictions": contradictions, "not_assessed_sections": [sec["title"] for sec in prof["sections"] if sec["state_note"]], "exposure": exp,
            "coverage": {"approved": cov["approved_tasks"], "completed": cov["completed_tasks"], "label": cov["label"]}, "citations": list(cites.values()),
            "authorization": prof["authorization"]["status"],
            "caveat": "Leads are not facts. Nothing here is verified unless it is listed under verified with its evidence. Absence of a result is not proof something does not exist."}


def _plan(db: Session, st: Any, s: Subject, case_id: str, tools: dict[str, dict[str, Any]]) -> dict[str, Any]:
    from ..db.models import Case
    case = db.get(Case, case_id)
    assert case is not None
    pv = research.preview(db, s, case, st.adapters, st.settings)
    cov = research.coverage(db, s, st.adapters)
    state = {c["source_id"]: c for cat in cov["categories"] for c in cat["cells"]}
    rec: dict[str, dict[str, Any]] = {}
    blocked: dict[str, dict[str, Any]] = {}
    for e in pv["entries"]:
        sid = e["source_id"]
        cell = state.get(sid, {})
        if cell.get("status") in ("completed", "running", "approved"):
            continue
        health = tools.get(sid, {}).get("status")
        if e["runnable"] and health in (None, "healthy"):
            score = CAT_WEIGHT.get(e["category"], 1) + MATURITY_BONUS.get(e["maturity"], 0) + (1 if cell.get("status") in ("outdated", "failed") else 0)
            rec.setdefault(sid, {"source": sid, "name": e["name"], "category": e["category"], "score": score, "needs_confirmation": e["requires_confirmation"],
                                 "maturity": e["maturity"].replace("_", " "), "status": cell.get("status", "not_run"), "inputs": 0,
                                 "why": f"{preg.CATEGORIES[e['category']]} has {'not run' if cell.get('status', 'not_run') == 'not_run' else cell.get('status')}; {e['legal_note']}"})
            rec[sid]["inputs"] += 1
        elif sid not in rec:
            blocked.setdefault(sid, {"source": sid, "name": e["name"], "reason": e["reason"] or (f"tool state: {health}" if health else "not runnable")})
    for sid, cell in state.items():
        if cell["status"] in ("unsupported", "unavailable") and sid not in rec and sid not in blocked:
            blocked[sid] = {"source": sid, "name": cell["name"], "reason": cell["detail"]}
    ranked = sorted(rec.values(), key=lambda r: (-r["score"], r["name"]))
    for i, r in enumerate(ranked, 1):
        r["rank"] = i
    manual = [{"name": c["name"], "why": c["detail"]} for c in state.values() if c["maturity"] == "manual" and c["status"] == "not_run"]
    return {"recommended": ranked, "not_recommended": sorted(blocked.values(), key=lambda b: b["name"]), "manual_methods": manual, "authorization": pv["authorization"]["status"],
            "note": "Only sources that policy and authorization currently allow are recommended. Nothing has been run; approve a plan on the Research screen.", "executed": False}


def _explain_claim(db: Session, s: Subject, claim_id: str) -> dict[str, Any]:
    if not claim_id:
        raise Refused("explain_claim needs claim_id")
    c = db.get(ProfileClaim, claim_id)
    if not c or c.subject_id != s.id:
        raise Refused("claim not found on this subject")
    others = [o for o in db.scalars(select(ProfileClaim).where(ProfileClaim.subject_id == s.id, ProfileClaim.field == c.field, ProfileClaim.id != c.id))
              if _text(o.structured_value).casefold() != _text(c.structured_value).casefold()]
    ev = _ev(db, c.evidence_ids)
    kinds = {db.get(Evidence, e["id"]).kind for e in ev if db.get(Evidence, e["id"])}   # type: ignore[union-attr]
    history = [{"from": h.from_state, "to": h.to_state, "by": h.reviewer, "basis": h.basis, "at": h.created_at.isoformat()}
               for h in db.scalars(select(ProfileReviewEvent).where(ProfileReviewEvent.target_id == c.id).order_by(ProfileReviewEvent.created_at))]
    why = {"verified": "A person verified it with the evidence below.", "subject_confirmed": "The subject attested to it.", "candidate": "Nobody has reviewed it; it is only a lead.",
           "conflicting": "It conflicts with other information.", "rejected": "A person rejected it.", "not_assessed": "It has not been assessed."}[c.validation_state]
    return {"claim": {"id": c.id, "field": c.field, "text": _text(c.structured_value), "state": pservice.LABELS[c.validation_state], "assertion_source": c.assertion_source},
            "confidence_rationale": f"{why} {len(ev)} evidence item(s) of {len(kinds)} kind(s) are attached; {c.assertion_source} asserted it.", "evidence": ev,
            "contradictions": [{"id": o.id, "text": _text(o.structured_value), "state": pservice.LABELS[o.validation_state], "evidence": _ev(db, o.evidence_ids)} for o in others],
            "review_history": history, "citations": ev}


def _queue(db: Session, s: Subject) -> dict[str, Any]:
    leads = candidates.list_candidates(db, s, "candidate") + candidates.list_candidates(db, s, "unsure")
    clusters: dict[str, list[dict[str, Any]]] = {}
    for k in leads:
        host = re.sub(r"^www\.", "", re.sub(r"^https?://", "", k["canonical_url"]).split("/")[0])
        clusters.setdefault(".".join(host.split(".")[-2:]), []).append(k)
    out = [{"site_family": fam, "count": len(rows), "candidate_ids": [r["id"] for r in rows], "urls": [r["canonical_url"] for r in rows],
            "tools": sorted({a for r in rows for a in r["adapters"]}), "suggested_order": "Review together; they come from the same site family."}
           for fam, rows in sorted(clusters.items(), key=lambda kv: (-len(kv[1]), kv[0]))]
    return {"clusters": out, "total_leads": len(leads), "changed": False,
            "note": "Grouping only. Nothing was merged, confirmed or rejected: decide each account on the Review queue with your own reason."}


def _explain_exposure(db: Session, s: Subject) -> dict[str, Any]:
    rows = []
    for x in db.scalars(select(ExposureIndicator).where(ExposureIndicator.subject_id == s.id).order_by(ExposureIndicator.last_checked.desc())):
        d = exposure.indicator_dict(x, redact=False)
        meaning = {"confirmed_exposure": "A source reported this exposure. See the remediation checklist.",
                   "not_found_in_checked_sources": "The checked sources did not report it. That does not prove it never happened.",
                   "not_assessed": "Nobody has checked this yet."}[x.status]
        rows.append({"class": d["class_label"], "result": d["status_label"], "risk": d["risk"], "date": str(d["exposure_date"] or ""), "descriptor": d["descriptor"],
                     "meaning": meaning, "remediation": exposure.CLASSES.get(x.cls, {}).get("guidance", []) if x.status == "confirmed_exposure" else [], "state": x.remediation_state})
    return {"indicators": rows, "never_shown": "Passwords, hashes, tokens, recovery secrets, government identifiers and breach dumps are never stored or shown.",
            "note": "Absent records mean not assessed." if not rows else ""}


def _guide(db: Session, s: Subject, image_id: str) -> dict[str, Any]:
    a = db.get(ImageAsset, image_id) if image_id else db.scalars(select(ImageAsset).where(ImageAsset.subject_id == s.id).order_by(ImageAsset.created_at.desc())).first()
    if not a or a.subject_id != s.id:
        raise Refused("no image found; import one on the Images screen first")
    g = images.reverse_search_guide(a)
    d = consent.check(db, s, "reverse_image")
    for p in g["providers"]:
        if not d.allowed:
            p["link"] = None
    g["authorization"] = {"allowed": d.allowed, "reason": d.reason}
    g["record_results"] = "After searching by hand, record each result page on the Images screen. The application never queries these providers and cannot confirm a search happened."
    return g


def _why_not(db: Session, st: Any, s: Subject, case_id: str, source: str, tools: dict[str, dict[str, Any]]) -> dict[str, Any]:
    from ..db.models import Case
    low = source.casefold().strip()
    match = next((v for v in preg.SOURCES.values() if v.id == low or v.label.casefold() == low or low in v.label.casefold() or v.id in low), None) if low else None
    if match is None:
        raise Refused("name a source (for example 'sherlock' or 'rdap')")
    case = db.get(Case, case_id)
    assert case is not None
    reasons: list[str] = []
    if match.manual:
        reasons.append(f"{match.label} is a manual method: nothing runs automatically. {match.legal_note}")
    else:
        pv = research.preview(db, s, case, st.adapters, st.settings)
        mine = [e for e in pv["entries"] if e["source_id"] == match.id]
        health = tools.get(match.id, {}).get("status")
        if not mine:
            reasons.append(f"{match.label} needs a {' or '.join(match.identifier_kinds)} input, and this subject has none.")
        else:
            for e in mine:
                if e["runnable"]:
                    reasons.append(f"{match.label} on this {e['identifier_kind']} input is eligible and has simply not been approved yet" + (f" (last status: {e['previous']['status']})" if e["previous"] else "") + ".")
                else:
                    reasons.append(f"{match.label}: {e['reason']}")
        if health and health != "healthy":
            reasons.append(f"The tool reports '{health.replace('_', ' ')}' on this machine.")
    return {"source": match.id, "name": match.label, "reasons": list(dict.fromkeys(reasons)), "maturity": match.maturity.replace("_", " "), "legal_note": match.legal_note}


def _image_match(db: Session, s: Subject, match_id: str) -> dict[str, Any]:
    q = select(ImageMatch).where(ImageMatch.subject_id == s.id)
    rows = [db.get(ImageMatch, match_id)] if match_id else list(db.scalars(q.where(ImageMatch.review_state == "candidate")))
    out = []
    for m in rows:
        if not m or m.subject_id != s.id:
            raise Refused("match not found on this subject")
        out.append(images.match_dict(db, m))
    return {"matches": out, "limits": images.LIMITS, "note": "A match is a candidate until a person reviews it. A provider page is not an identification of anyone."}


# ---------------------------------------------------------------------------------------------------------------------------- cloud view
def cloud_view(name: str, r: dict[str, Any]) -> dict[str, Any]:
    """What a cloud model may be shown: counts and generic text only. No identifiers, URLs, descriptors, titles or coordinates."""
    if name in AIV_READ_TOOLS:
        from . import aiv_tools
        return aiv_tools.cloud_view(name, r)
    if name in DARK_READ_TOOLS:
        from . import darkint_tools
        return darkint_tools.cloud_view(name, r)
    if name in EMAIL_READ_TOOLS:
        from . import email_tools
        return email_tools.cloud_view(name, r)
    notice = "Profile details are withheld from cloud models; only counts and generic text are shown."
    if name == "summarize_profile":
        return {"counts": {"verified": len(r["verified"]), "confirmed_accounts": len(r["confirmed_accounts"]), "unverified_leads": len(r["unverified_leads"]), "contradictions": len(r["contradictions"])},
                "sections_not_assessed": r["not_assessed_sections"], "coverage": r["coverage"], "authorization": r["authorization"], "caveat": r["caveat"], "notice": notice}
    if name == "recommend_research_plan":
        return {"recommended": [{"rank": x["rank"], "source": x["source"], "needs_confirmation": x["needs_confirmation"], "status": x["status"]} for x in r["recommended"]],
                "blocked_count": len(r["not_recommended"]), "notice": notice}
    if name == "explain_claim":
        return {"state": r["claim"]["state"], "field": r["claim"]["field"], "evidence_count": len(r["evidence"]), "contradiction_count": len(r["contradictions"]), "notice": notice}
    if name == "create_verification_queue":
        return {"clusters": [{"count": c["count"]} for c in r["clusters"]], "total_leads": r["total_leads"], "notice": notice}
    if name == "explain_exposure":
        return {"indicators": [{"class": i["class"], "result": i["result"], "risk": i["risk"]} for i in r["indicators"]], "notice": notice}
    if name == "guide_image_search":
        return {"steps": r["steps"], "limits": r["limits"], "notice": notice}
    if name == "why_not_searched":
        return {"source": r["source"], "reasons_count": len(r["reasons"]), "notice": notice}
    if name == "explain_image_match":
        return {"match_count": len(r["matches"]), "limits": r["limits"], "notice": notice}
    return {"notice": notice}


# ---------------------------------------------------------------------------------------------------------------------------- proposals
def propose(db: Session, st: Any, user: str, case_id: str, name: str, args: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    if name in AIV_ACTION_TOOLS:
        from . import aiv_tools
        return aiv_tools.propose(db, st, user, case_id, args)
    if name in DARK_ACTION_TOOLS:
        from . import darkint_tools
        return darkint_tools.propose(db, st, user, case_id, args)
    if name in EMAIL_ACTION_TOOLS:
        from . import email_tools
        return email_tools.propose(db, st, user, case_id, args)
    role = _role(db, user, case_id)
    _need(role, "editor", name.replace("_", " "))
    s = _subject(db, case_id, args)
    if name == "propose_enrichment_workflow":
        from ..automations import catalog
        slug = str(args.get("slug") or args.get("template") or "").strip().lower()
        t = catalog.get(slug)
        if not t or t["category"] != "Target profile":
            raise Refused("name one of the Target profile templates (TP-01 to TP-12)")
        inputs = args.get("inputs") or {}
        if not isinstance(inputs, dict) or not all(isinstance(k, str) and isinstance(v, str | int | float | bool | type(None)) for k, v in inputs.items()):
            raise Refused("inputs must be a simple object")
        for k in inputs:
            if k not in t["definition"]["inputs"]:
                raise Refused(f"template {t['key']} has no input '{k}'")
        adapters = sorted({n["config"]["adapter"] for n in t["definition"]["nodes"] if n["type"] in ("adapter_query", "enrich")})
        classes = sorted({preg.SOURCES[a].source_class for a in adapters if a in preg.SOURCES})
        problems = []
        for cls in classes:
            d = consent.check(db, s, cls)
            if not d.allowed:
                problems.append(f"{cls}: {d.reason}")
        if problems:
            raise Refused("not proposed: this subject is not authorized for " + "; ".join(problems))
        clean = {"slug": t["slug"], "inputs": inputs, "subject_id": s.id}
        preview = {"template": f"{t['key']} {t['name']}", "will_contact": {a: st.adapters[a].manifest.endpoints for a in adapters if a in st.adapters}, "keys_needed": sorted({st.adapters[a].manifest.api_key_name for a in adapters if a in st.adapters and st.adapters[a].manifest.api_key_name}),
                   "capability_gaps": t["capability_gaps"], "installs": "a DISABLED draft bound to this subject; running it later needs approval, activation and live authorization",
                   "classes": classes}
        return clean, preview
    if name == "draft_subject_report":
        aud = args.get("audience", "subject")
        if aud not in reports.AUDIENCES:
            raise Refused("audience must be 'subject' or 'analyst'")
        return {"audience": aud, "subject_id": s.id}, {"audience": aud, "produces": "a DRAFT preview with a citation check. Nothing is exported; export is a separate button after you read it."}
    raise Refused(f"'{name}' is not a profile action")


def execute(db: Session, st: Any, user: str, case_id: str, name: str, a: dict[str, Any]) -> dict[str, Any]:
    if name in DARK_ACTION_TOOLS:
        from . import darkint_tools
        return darkint_tools.execute(db, st, user, case_id, a)
    role = _role(db, user, case_id)
    _need(role, "editor", name.replace("_", " "))
    s = _subject(db, case_id, {"subject_id": a.get("subject_id")})
    if name == "propose_enrichment_workflow":
        from ..db.models import Case
        case = db.get(Case, case_id)
        assert case is not None
        try:
            wf = hooks.install_template(db, s, case, a["slug"], a.get("inputs") or {}, user)
        except hooks.InstallError as exc:
            raise Refused(str(exc)) from exc
        return {"executed": True, "workflow_id": wf.id, "state": wf.state, "note": "Installed as a disabled draft bound to this subject. Open Automations to review, dry-run and request approval."}
    if name == "draft_subject_report":
        rep = reports.build(db, s, audience=a["audience"], role=role, adapters=st.adapters)
        check = reports.verify_citations(db, st.vault, rep, case_id)
        return {"executed": True, "draft": True, "markdown": reports.to_markdown(rep)[:12000], "citation_check": check,
                "note": "This is a draft in the conversation only. Open Target profile > Reports to review and export it."}
    raise Refused(f"'{name}' is not a profile action")
