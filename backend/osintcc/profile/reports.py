"""Subject reports with traceable statements.

Two audiences, one data model:
  * `subject`  : the redacted, client-facing report. Verified statements only; leads are counted, never described; exposure details are limited to
                 class, result, risk and remediation; precise locations and identifier values are left out.
  * `analyst`  : the private evidence package. Leads, conflicts, review history, descriptors, coarse GPS and the research coverage detail.
Every statement carries the evidence ids it rests on. `verify_citations` re-checks each one against the case and the vault before anything is exported.
Speculative associations (relatives, addresses, anyone else's accounts) have no place in either report, because the profile cannot hold them.
"""
from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db.models import (
    Evidence,
    ExposureIndicator,
    ImageAsset,
    ImageMatch,
    ProfileClaim,
    ProfileReviewEvent,
    RemediationTask,
    Subject,
    SubjectCorrection,
)
from ..evidence.vault import IntegrityError, Vault, VaultError
from . import candidates, consent, exposure, images, research
from .service import LABELS, ProfileError

AUDIENCES = ("subject", "analyst")
LIMITS = [
    "Information in this report is only as good as the public sources and evidence cited next to it. Public sources can be wrong, outdated or manipulated.",
    "Absence of a result is never proof that information does not exist. 'Not found in checked sources' describes only the sources that were checked.",
    "Matching handles or similar images are leads. Nothing is attributed to a person unless it is listed as verified with its evidence.",
    "No facial recognition or identification of people from images was performed.",
]


def _now() -> datetime:
    return datetime.now(UTC)


def _text(v: Any) -> str:
    if isinstance(v, dict):
        return str(v.get("text") or v.get("url") or json.dumps(v, sort_keys=True, default=str))
    return str(v)


def build(db: Session, subject: Subject, *, audience: str, role: str, adapters: dict | None = None) -> dict[str, Any]:
    if audience not in AUDIENCES:
        raise ProfileError("invalid_audience", "audience must be subject or analyst")
    if audience == "analyst" and role == "viewer":
        raise ProfileError("role_required", "the analyst evidence package needs an editor or owner")
    analyst = audience == "analyst"
    stmts: list[dict[str, Any]] = []
    ev_ids: list[str] = []

    def add(section: str, text: str, kind: str, evidence_ids: list[str] | None = None, **extra: Any) -> None:
        ids = [e for e in dict.fromkeys(evidence_ids or [])]
        for e in ids:
            if e not in ev_ids:
                ev_ids.append(e)
        stmts.append({"id": f"S{len(stmts) + 1}", "section": section, "text": text, "kind": kind, "evidence_ids": ids, **extra})

    # --- verified information --------------------------------------------------------------------------------------------------------------
    claims = list(db.scalars(select(ProfileClaim).where(ProfileClaim.subject_id == subject.id).order_by(ProfileClaim.created_at)))
    for c in claims:
        if c.validation_state in ("verified", "subject_confirmed"):
            if c.sensitivity == "RESTRICTED" and not analyst:
                continue
            who = "confirmed by the subject" if c.validation_state == "subject_confirmed" else "verified"
            add("verified", f"{c.field.replace('_', ' ').capitalize()}: {_text(c.structured_value)} ({who})", "verified", c.evidence_ids, claim_id=c.id)
    cands = candidates.list_candidates(db, subject)
    for k in cands:
        if k["state"] == "confirmed":
            add("verified", f"Public account confirmed as the subject's: {k['canonical_url']}", "verified", [e["id"] for e in k["evidence"]], candidate_id=k["id"])
    # --- leads, conflicts: counted for the subject, detailed for the analyst ----------------------------------------------------------------------
    leads = [k for k in cands if k["state"] in ("candidate", "unsure")]
    if analyst:
        for k in leads:
            add("leads", f"LEAD (unverified, {k['state']}): {k['canonical_url']} seen by {', '.join(k['adapters'])}; {k['independent_signals']} independent signal(s). {k['note']}".strip(),
                "lead", [e["id"] for e in k["evidence"]], candidate_id=k["id"])
        for c in claims:
            if c.validation_state in ("candidate", "conflicting", "rejected"):
                add("leads", f"CLAIM {LABELS[c.validation_state].upper()}: {c.field.replace('_', ' ')}: {_text(c.structured_value)}" + (f" ({c.reason})" if c.reason else ""), "lead", c.evidence_ids, claim_id=c.id)
    else:
        n_claims = sum(1 for c in claims if c.validation_state in ("candidate", "conflicting"))
        add("not_verified", f"{len(leads)} public account lead(s) and {n_claims} unverified claim(s) exist and are not included in this report because they are not verified.", "note")
    # --- exposure ------------------------------------------------------------------------------------------------------------------------
    for x in db.scalars(select(ExposureIndicator).where(ExposureIndicator.subject_id == subject.id).order_by(ExposureIndicator.last_checked)):
        d = exposure.indicator_dict(x, redact=not analyst)
        line = f"{d['class_label']}: {d['status_label']}" + (f", risk {d['risk']}" if x.status == "confirmed_exposure" else "") + (f", remediation {d['remediation_state']}" if x.status == "confirmed_exposure" else "")
        if analyst and d["descriptor"]:
            line += f" ({d['descriptor']})"
        if d["caveat"]:
            line += f". {d['caveat']}"
        add("exposure", line, "exposure", [x.evidence_id] if x.evidence_id else [], indicator_id=x.id)
    # --- remediation ------------------------------------------------------------------------------------------------------------------
    for t in db.scalars(select(RemediationTask).where(RemediationTask.subject_id == subject.id).order_by(RemediationTask.created_at)):
        add("remediation", f"{t.issue[:200]} ({t.state.replace('_', ' ')}, priority {t.priority})", "remediation", [t.resolution_evidence_id] if t.resolution_evidence_id else [], task_id=t.id)
    # --- images --------------------------------------------------------------------------------------------------------------------------
    imgs = list(db.scalars(select(ImageAsset).where(ImageAsset.subject_id == subject.id)))
    if imgs:
        gps = sum(1 for a in imgs if a.has_gps)
        add("images", f"{len(imgs)} image(s) reviewed; {gps} contain location metadata" + (" (shown at about 10 km precision in this report)" if analyst else " (coordinates are not included in this report)"), "note",
            [a.evidence_id for a in imgs])
        if analyst:
            for m in db.scalars(select(ImageMatch).where(ImageMatch.subject_id == subject.id)):
                add("images", f"Image match {m.match_type.replace('_', ' ')} ({m.review_state})" + (f" at {m.matched_url}" if m.matched_url else "") + ". " + images.LIMITS[:90] + "…", "lead", m.evidence_ids)
            for a in imgs:
                if a.has_gps:
                    g = (a.metadata_json or {}).get("gps") or {}
                    add("images", f"Image {a.sha256[:10]} location metadata (coarse): {images.coarse(g.get('lat', 0))}, {images.coarse(g.get('lon', 0))}", "note", [a.evidence_id])
    # --- coverage ------------------------------------------------------------------------------------------------------------------------
    cov = research.coverage(db, subject, adapters or {})
    add("coverage", f"{cov['completed_tasks']} of {cov['approved_tasks']} approved research task(s) completed. {cov['label']}", "note")
    if analyst:
        for cat in cov["categories"]:
            for cell in cat["cells"]:
                add("coverage", f"{cat['title']}: {cell['name']} is {cell['status'].replace('_', ' ')}" + (f" ({cell['detail']})" if cell["detail"] else ""), "note")
        for rv in db.scalars(select(ProfileReviewEvent).where(ProfileReviewEvent.subject_id == subject.id).order_by(ProfileReviewEvent.created_at)):
            add("history", f"{rv.created_at:%Y-%m-%d %H:%M} {rv.target_type} {rv.from_state} to {rv.to_state} by {rv.reviewer}: {rv.basis[:160]}", "note", rv.evidence_ids)
        for corr in db.scalars(select(SubjectCorrection).where(SubjectCorrection.subject_id == subject.id)):
            add("history", f"Correction request ({corr.status}): {corr.request_text[:160]}", "note")
    # --- evidence manifest ----------------------------------------------------------------------------------------------------------------
    manifest = []
    for i, eid in enumerate(ev_ids, 1):
        e = db.get(Evidence, eid)
        if e:
            manifest.append({"ref": f"E{i}", "id": e.id, "title": e.title, "kind": e.kind, "sha256": e.sha256, "retrieved_at": e.retrieved_at.isoformat() if e.retrieved_at else None,
                             "url": e.original_url if analyst else None})
        else:
            manifest.append({"ref": f"E{i}", "id": eid, "title": "", "kind": "missing", "sha256": "", "retrieved_at": None, "url": None})
    refs = {m["id"]: m["ref"] for m in manifest}
    for s in stmts:
        s["refs"] = [refs[e] for e in s["evidence_ids"] if e in refs]
    header = {"subject": subject.display_name, "mode": subject.mode, "audience": audience, "generated_at": _now().isoformat(),
              "authorization": _auth_line(db, subject), "status": "DRAFT: not exported until a person approves it"}
    body = {"header": header, "statements": stmts, "evidence": manifest, "limits": LIMITS,
            "corrections": "The subject may ask for any statement to be corrected or removed; requests are recorded and answered with a reason."}
    body["manifest_sha256"] = hashlib.sha256(json.dumps(manifest, sort_keys=True, default=str).encode()).hexdigest()
    return body


def _auth_line(db: Session, subject: Subject) -> str:
    a = consent.current_status(db, subject)
    if a["status"] == "active":
        return f"{a['verification_method'].replace('_', ' ')} by {a.get('verifier', '')}; valid until {str(a['expires_at'])[:10]}; classes: {', '.join(a['source_classes'])}"
    return a["status"].replace("_", " ")


def verify_citations(db: Session, vault: Vault | None, report: dict[str, Any], case_id: str) -> dict[str, Any]:
    """Every statement presented as verified must resolve to case evidence whose stored bytes still match their hash."""
    problems: list[str] = []
    warnings: list[str] = []
    by_id = {m["id"]: m for m in report["evidence"]}
    checked: dict[str, str] = {}
    for s in report["statements"]:
        if s["kind"] not in ("verified", "exposure_verified") and not s["evidence_ids"]:
            continue
        if s["kind"] == "verified" and not s["evidence_ids"]:
            problems.append(f"{s['id']}: a verified statement has no evidence")
        for eid in s["evidence_ids"]:
            if eid in checked:
                if checked[eid] and s["kind"] == "verified":
                    problems.append(f"{s['id']}: {checked[eid]}")
                continue
            e = db.get(Evidence, eid)
            msg = ""
            if e is None or e.case_id != case_id:
                msg = f"evidence {eid[:8]} is not in this case"
            elif e.redacted:
                msg = f"evidence {eid[:8]} was redacted or purged"
            elif by_id.get(eid, {}).get("sha256") != e.sha256:
                msg = f"evidence {eid[:8]} hash differs from the manifest"
            elif e.vault_relpath and vault is not None:
                try:
                    vault.read(e.vault_relpath, e.sha256)
                except (IntegrityError, VaultError, OSError) as exc:
                    msg = f"evidence {eid[:8]} failed its integrity check ({type(exc).__name__})"
            elif not e.vault_relpath:
                warnings.append(f"evidence {eid[:8]} is reference-only: its content was never stored here, so it cannot be re-verified")
            checked[eid] = msg
            if msg and s["kind"] == "verified":
                problems.append(f"{s['id']}: {msg}")
    return {"ok": not problems, "problems": problems, "warnings": sorted(set(warnings)), "statements_checked": sum(1 for s in report["statements"] if s["kind"] == "verified"),
            "evidence_checked": len(checked)}


def to_markdown(report: dict[str, Any]) -> str:
    h = report["header"]
    out = [f"# Target profile report: {h['subject']}", "", f"*{h['status']}*", "",
           f"- Audience: **{h['audience']}**  ·  Mode: {h['mode'].replace('_', ' ')}  ·  Generated: {h['generated_at'][:19]}Z", f"- Authorization: {h['authorization']}", ""]
    titles = {"verified": "Verified information", "not_verified": "Not included", "leads": "Leads and unverified claims (analyst only)", "exposure": "Exposure indicators",
              "remediation": "Remediation", "images": "Images", "coverage": "Research coverage", "history": "Decision history and corrections"}
    for sec, title in titles.items():
        rows = [s for s in report["statements"] if s["section"] == sec]
        if not rows:
            continue
        out += [f"## {title}", ""]
        for s in rows:
            cite = " " + "".join(f"[{r}]" for r in s["refs"]) if s["refs"] else ""
            out.append(f"- {s['text']}{cite}")
        out.append("")
    if not any(s["section"] == "verified" for s in report["statements"]):
        out += ["## Verified information", "", "Nothing has been verified yet.", ""]
    out += ["## Limits", ""] + [f"- {x}" for x in report["limits"]] + ["", "## Corrections", "", report["corrections"], "", "## Evidence", ""]
    for m in report["evidence"]:
        out.append(f"- **{m['ref']}** {m['title'] or m['kind']} · sha256 `{m['sha256'][:16]}…` · retrieved {str(m['retrieved_at'])[:10]}" + (f" · {m['url']}" if m.get("url") else ""))
    out += ["", f"Evidence manifest sha256: `{report['manifest_sha256']}`", ""]
    return "\n".join(out)


def to_html(report: dict[str, Any]) -> str:
    from ..reporting.build import render_markdown_safe
    return ("<!doctype html><html><head><meta charset='utf-8'><title>Target profile report</title></head><body>" + render_markdown_safe(to_markdown(report)) + "</body></html>")
