"""Associated emails and the cross-INT expansion plan (Associated Email Discovery addendum). Same conventions as profile.py.

Request models forbid unknown fields, so a body carrying a password, hash, token or similar is refused before any code runs.
"""
from __future__ import annotations

import asyncio
from typing import Literal

from fastapi import APIRouter, Request
from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt
from sqlalchemy import select

from ...db.models import AssociatedEmail, Subject
from ...profile import emails, expansion, research
from ...profile.service import ProfileError
from ...telemetry import audit
from .profile import perr, subject_for
from .routes import S, actor

router: APIRouter = APIRouter()


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


@router.get("/subjects/{subject_id}/associated-emails")
async def list_emails(request: Request, subject_id: str):
    st = S(request)
    with st.sm() as db:
        s, case, role = subject_for(db, request, subject_id)
        if role in ("owner", "editor"):
            emails.sweep(db, s, actor(request))
            audit.record(db, "profile.emails_view", actor=actor(request), case_id=case.id, resource_type="subject", resource_id=s.id)
            db.commit()
        return {**emails.list_for(db, st, s, role=role), "role": role}


@router.post("/subjects/{subject_id}/associated-emails/discover")
async def discover(request: Request, subject_id: str):
    """Folds addresses that stored evidence already shows into candidates (no network) and previews the expansion plan that could find more."""
    st = S(request)
    with st.sm() as db:
        s, case, _ = subject_for(db, request, subject_id, "editor")
        research.refresh_tasks(db, s)
        swept = emails.sweep(db, s, actor(request))
        p = expansion.plan(db, s, case, st.adapters, st.settings)
        db.commit()
        return {"swept": swept, "plan_steps": len(p["steps"]), "executable_now": sum(1 for x in p["steps"] if x["executable_now"]), "stop_reason": p["stop_reason"],
                "speculative": emails.speculate(db, s), "note": "Nothing was sent. Pattern guesses are suggestions only."}


class ManualIn(Strict):
    address: str = Field(min_length=3, max_length=254)
    evidence_id: str | None = None
    url: str = Field(default="", max_length=300)
    note: str = Field(default="", max_length=1000)


@router.post("/subjects/{subject_id}/associated-emails", status_code=201)
async def add_email(request: Request, subject_id: str, body: ManualIn):
    st = S(request)
    with st.sm() as db:
        s, _, role = subject_for(db, request, subject_id, "editor")
        try:
            r = emails.add_manual(db, s, body.address, evidence_id=body.evidence_id, url=body.url, note=body.note, actor=actor(request))
        except ProfileError as exc:
            db.commit()
            raise perr(exc) from exc
        db.commit()
        return emails.email_dict(db, st, s, r, redact=role not in ("owner", "editor"))


class SpeculativeIn(Strict):
    address: str = Field(min_length=3, max_length=254)


@router.post("/subjects/{subject_id}/associated-emails/speculative", status_code=201)
async def accept_speculative(request: Request, subject_id: str, body: SpeculativeIn):
    st = S(request)
    with st.sm() as db:
        s, _, _ = subject_for(db, request, subject_id, "editor")
        try:
            r = emails.accept_speculative(db, s, body.address, actor(request))
        except ProfileError as exc:
            raise perr(exc) from exc
        db.commit()
        return emails.email_dict(db, st, s, r, redact=False)


class ReviewIn(Strict):
    ids: list[str] = Field(min_length=1, max_length=200)
    to_state: Literal["confirmed", "rejected", "candidate"]
    basis: str = Field(min_length=1, max_length=2000)
    attestation: Literal["none", "subject"] = "none"
    evidence_ids: list[str] = Field(default_factory=list, max_length=20)


@router.post("/subjects/{subject_id}/associated-emails/review")
async def review_emails(request: Request, subject_id: str, body: ReviewIn):
    with S(request).sm() as db:
        s, _, _ = subject_for(db, request, subject_id, "editor")
        try:
            out = emails.review(db, s, body.ids, to_state=body.to_state, reviewer=actor(request), basis=body.basis, attestation=body.attestation, evidence_ids=body.evidence_ids)
        except ProfileError as exc:
            db.commit()
            raise perr(exc) from exc
        db.commit()
        return out


class NoteIn(Strict):
    note: str = Field(max_length=1000)


@router.patch("/subjects/{subject_id}/associated-emails/{email_id}")
async def annotate_email(request: Request, subject_id: str, email_id: str, body: NoteIn):
    st = S(request)
    with st.sm() as db:
        s, _, _ = subject_for(db, request, subject_id, "editor")
        try:
            r = emails.annotate(db, s, email_id, body.note, actor(request))
        except ProfileError as exc:
            raise perr(exc) from exc
        db.commit()
        return emails.email_dict(db, st, s, r, redact=False)


class MergeIn(Strict):
    keep_id: str
    merge_ids: list[str] = Field(min_length=1, max_length=20)


@router.post("/subjects/{subject_id}/associated-emails/merge")
async def merge_emails(request: Request, subject_id: str, body: MergeIn):
    st = S(request)
    with st.sm() as db:
        s, _, _ = subject_for(db, request, subject_id, "editor")
        try:
            r = emails.merge(db, s, body.keep_id, body.merge_ids, actor(request))
        except ProfileError as exc:
            db.commit()
            raise perr(exc) from exc
        db.commit()
        return emails.email_dict(db, st, s, r, redact=False)


@router.post("/subjects/{subject_id}/associated-emails/{email_id}/promote")
async def promote_email(request: Request, subject_id: str, email_id: str):
    """Adds a CONFIRMED address as one of the subject's inputs. It is then covered by research and exposure checks only if the authorization covers it."""
    with S(request).sm() as db:
        s, _, _ = subject_for(db, request, subject_id, "editor")
        try:
            ident = emails.promote(db, s, email_id, actor(request))
        except ProfileError as exc:
            db.commit()
            raise perr(exc) from exc
        db.commit()
        return {"identifier_id": ident.id, "note": "Added as an input. Research and exposure checks still need the authorization to cover it."}


# ---- cross-INT expansion --------------------------------------------------------------------------------------------------------------------
@router.get("/subjects/{subject_id}/expansion")
async def expansion_plan(request: Request, subject_id: str):
    st = S(request)
    with st.sm() as db:
        s, case, _ = subject_for(db, request, subject_id, "editor")
        research.refresh_tasks(db, s)
        emails.sweep(db, s, actor(request))
        out = expansion.plan(db, s, case, st.adapters, st.settings)
        db.commit()
        return {**out, "history": expansion.history(db, s)}


class PolicyIn(Strict):
    max_depth: StrictInt | None = None
    max_runs: StrictInt | None = None
    max_per_pass: StrictInt | None = None
    auto_passive: StrictBool | None = None


@router.put("/subjects/{subject_id}/expansion/policy")
async def expansion_policy(request: Request, subject_id: str, body: PolicyIn):
    with S(request).sm() as db:
        s, _, _ = subject_for(db, request, subject_id, "owner")          # widening what runs on its own is the case owner's decision
        try:
            pol = expansion.set_policy(db, s, {k: v for k, v in body.model_dump().items() if v is not None}, actor(request))
        except ProfileError as exc:
            raise perr(exc) from exc
        db.commit()
        return pol


class RunIn(Strict):
    keys: list[str] | None = Field(default=None, max_length=40)
    confirmed_sources: list[str] = Field(default_factory=list, max_length=10)
    promote_confirmed: bool = False
    wait: bool = False


@router.post("/subjects/{subject_id}/expansion/run", status_code=202)
async def expansion_run(request: Request, subject_id: str, body: RunIn):
    st = S(request)
    with st.sm() as db:
        s, case, _ = subject_for(db, request, subject_id, "editor")
        try:
            out = expansion.run(db, s, case, st.adapters, st.settings, actor=actor(request), keys=body.keys, confirmed_sources=body.confirmed_sources, promote=body.promote_confirmed)
        except ProfileError as exc:
            db.commit()
            raise perr(exc) from exc
        db.commit()

    async def finish(rid: str) -> None:
        await st.runner.run_until_idle(rid)
        with st.sm() as db2:
            sub = db2.get(Subject, subject_id)
            if sub:
                research.refresh_tasks(db2, sub)
                emails.sweep(db2, sub, "system")
                db2.commit()

    for rid in out["run_ids"]:
        if body.wait:
            await finish(rid)
        else:
            t = asyncio.create_task(finish(rid))
            st.tasks.add(t)
            t.add_done_callback(st.tasks.discard)
    return out


@router.get("/subjects/{subject_id}/associated-emails/count")
async def count(request: Request, subject_id: str):
    with S(request).sm() as db:
        s, _, _ = subject_for(db, request, subject_id)
        rows = db.scalars(select(AssociatedEmail.classification).where(AssociatedEmail.subject_id == s.id)).all()
        return {c: sum(1 for x in rows if x == c) for c in emails.CLASSES}
