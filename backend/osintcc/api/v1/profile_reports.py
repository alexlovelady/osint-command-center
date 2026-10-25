"""Subject reports (addendum TP-1.0 sections 7, 9): preview, citation check, sealed export. Nothing is exported without an explicit create call."""
from __future__ import annotations

import asyncio
import json
from typing import Literal

from fastapi import APIRouter, Request
from pydantic import BaseModel
from sqlalchemy import select

from ...db.models import ReportRun, Subject
from ...evidence.vault import VaultLocked
from ...main import ApiError
from ...profile import reports
from ...profile.service import ProfileError
from ...reporting import store as report_store
from ...telemetry import audit
from .profile import perr, subject_for
from .routes import S, actor

router: APIRouter = APIRouter()


class ReportIn(BaseModel):
    audience: Literal["subject", "analyst"] = "subject"
    format: Literal["markdown", "html", "json"] = "markdown"


def _data(db, st, s: Subject, role: str, audience: str):
    try:
        rep = reports.build(db, s, audience=audience, role=role, adapters=st.adapters)
    except ProfileError as exc:
        raise perr(exc) from exc
    return rep, reports.verify_citations(db, st.vault, rep, s.case_id)


@router.post("/subjects/{subject_id}/report/preview")
async def report_preview(request: Request, subject_id: str, body: ReportIn):
    st = S(request)
    with st.sm() as db:
        s, case, role = subject_for(db, request, subject_id, "editor")
        rep, check = _data(db, st, s, role, body.audience)
        audit.record(db, "profile.report_preview", actor=actor(request), case_id=case.id, resource_type="subject", resource_id=s.id, metadata={"audience": body.audience})
        db.commit()
        return {"report": rep, "markdown": reports.to_markdown(rep), "citation_check": check, "exported": False}


@router.post("/subjects/{subject_id}/report/create", status_code=201)
async def report_create(request: Request, subject_id: str, body: ReportIn):
    st = S(request)
    with st.sm() as db:
        s, case, role = subject_for(db, request, subject_id, "editor")
        rep, check = _data(db, st, s, role, body.audience)
        if not check["ok"]:
            audit.record(db, "profile.report_refused", actor=actor(request), case_id=case.id, resource_type="subject", resource_id=s.id, decision="deny",
                         metadata={"problems": len(check["problems"])})
            db.commit()
            raise ApiError(409, "citation_check_failed", "the report was not created: " + "; ".join(check["problems"][:3]), False, {"problems": check["problems"]})
        rep["header"]["status"] = "Approved for export by " + actor(request)
        rr = ReportRun(case_id=case.id, template=f"subject-{body.audience}", redaction_profile=body.audience, evidence_manifest_sha256=rep["manifest_sha256"], status="running")
        db.add(rr)
        db.flush()
        stem = f"profile-{body.audience}-{s.id[:8]}-{rr.id[:8]}"
        out_dir = st.settings.export_dir
        out_dir.mkdir(parents=True, exist_ok=True)
        path = out_dir / (stem + {"markdown": ".md", "html": ".html", "json": ".json"}[body.format])
        text = reports.to_markdown(rep) if body.format == "markdown" else reports.to_html(rep) if body.format == "html" else json.dumps(rep, indent=2, sort_keys=True, default=str)
        path.write_text(text, encoding="utf-8")
        try:
            path, digest = await asyncio.to_thread(report_store.seal, st.vault, rr.id, path)
        except VaultLocked as exc:
            rr.status = "failed"
            db.commit()
            raise ApiError(503, "vault_locked", str(exc)) from exc
        rr.export_path, rr.status, rr.sha256 = path.name, "done", digest
        audit.record(db, "profile.report_export", actor=actor(request), case_id=case.id, resource_type="report", resource_id=rr.id,
                     metadata={"audience": body.audience, "format": body.format, "statements": len(rep["statements"])})
        db.commit()
        return {"id": rr.id, "file": path.name, "sha256": digest, "evidence_manifest_sha256": rep["manifest_sha256"], "citation_check": check, "audience": body.audience}


@router.get("/subjects/{subject_id}/reports")
async def list_reports(request: Request, subject_id: str):
    with S(request).sm() as db:
        s, case, _ = subject_for(db, request, subject_id, "editor")
        rows = db.scalars(select(ReportRun).where(ReportRun.case_id == case.id, ReportRun.template.like("subject-%")).order_by(ReportRun.generated_at.desc())).all()
        return {"items": [{"id": r.id, "audience": r.redaction_profile, "file": r.export_path, "sha256": r.sha256, "generated_at": r.generated_at, "status": r.status} for r in rows],
                "subject": s.id}
