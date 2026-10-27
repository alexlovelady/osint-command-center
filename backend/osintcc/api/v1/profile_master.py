"""Master Profile Editor API (Master Target Profile addendum, TPM1/TPM3/TPM5). Same conventions as profile.py.

Restricted values are filtered here, on the server: viewers do not receive them, editors see them masked, and only the case owner can reveal one (audited).
Request models forbid unknown fields, so a body carrying a password, token or similar is refused before any code runs.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, ConfigDict, Field

from ...main import ApiError
from ...profile import accounting, gaps, master, providers
from ...profile.service import ProfileError
from ...telemetry import audit
from .profile import perr, subject_for
from .routes import S, actor, require_admin

router: APIRouter = APIRouter()


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


@router.get("/subjects/{subject_id}/master")
async def get_master(request: Request, subject_id: str, state: str | None = None, q: str | None = None):
    """Sections, the research gaps panel and the next actions in one document."""
    st = S(request)
    with st.sm() as db:
        s, case, role = subject_for(db, request, subject_id)
        if state and state not in master.DISPLAY_STATES:
            raise ApiError(422, "invalid_state", f"state must be one of {', '.join(master.DISPLAY_STATES)}")
        doc = master.sections(db, st, s, role=role, state=state, q=(q or "")[:100] or None)
        analysis = gaps.analyze(db, st, s, case, st.adapters, st.settings, role=role) if role != "viewer" else None
        if role in ("owner", "editor"):
            audit.record(db, "profile.master_view", actor=actor(request), case_id=case.id, resource_type="subject", resource_id=s.id)
        db.commit()
        return {**doc, "subject": {"id": s.id, "display_name": s.display_name, "mode": s.mode, "purpose": s.purpose, "type": s.type}, "gaps": analysis,
                "duplicates": master.duplicates(db, s) if role != "viewer" else []}


class ItemIn(Strict):
    type: str
    value: str = Field(min_length=1, max_length=600)
    origin: Literal["subject_provided", "analyst_supplied", "published_source", "verified_provider"] = "analyst_supplied"
    source: str = Field(default="", max_length=80)
    evidence_ids: list[str] = Field(default_factory=list, max_length=20)
    attributes: dict[str, Any] = Field(default_factory=dict)
    observed_at: datetime | None = None
    confidence: Literal["unknown", "low", "medium", "high"] = "unknown"
    custom_type: str = Field(default="", max_length=60)
    note: str = Field(default="", max_length=1000)
    need_to_know: str = Field(default="", max_length=500)


@router.post("/subjects/{subject_id}/master/items", status_code=201)
async def add_item(request: Request, subject_id: str, body: ItemIn):
    st = S(request)
    with st.sm() as db:
        s, _, role = subject_for(db, request, subject_id, "editor")
        try:
            it, created = master.add_item(db, s, type=body.type, value=body.value, role=role, actor=actor(request), origin=body.origin, evidence_ids=body.evidence_ids, source_id=body.source,
                                          attributes=body.attributes, observed_at=body.observed_at, confidence=body.confidence, custom_type=body.custom_type, note=body.note,
                                          need_to_know=body.need_to_know)
        except ProfileError as exc:
            db.commit()
            raise perr(exc) from exc
        db.commit()
        return {**master.item_dict(db, it, role=role), "created": created}


class BatchIn(Strict):
    rows: list[dict[str, Any]] | None = Field(default=None, max_length=master.MAX_ROWS)
    kind: Literal["csv", "json"] | None = None
    content: str | None = Field(default=None, max_length=1_000_000)


@router.post("/subjects/{subject_id}/master/items/batch")
async def batch_items(request: Request, subject_id: str, body: BatchIn):
    """Several values at once, as rows or as a CSV / JSON file (columns: type, value, origin, source, evidence_ids, note). Bad rows are reported; good rows are kept."""
    with S(request).sm() as db:
        s, _, role = subject_for(db, request, subject_id, "editor")
        try:
            rows = body.rows if body.rows is not None else master.parse_import(body.kind or "json", body.content or "")
            out = master.batch_add(db, s, rows, role=role, actor=actor(request))
        except ProfileError as exc:
            db.commit()
            raise perr(exc) from exc
        db.commit()
        return out


class EditIn(Strict):
    value: str | None = Field(default=None, max_length=600)
    note: str | None = Field(default=None, max_length=1000)
    attributes: dict[str, Any] | None = None
    confidence: Literal["unknown", "low", "medium", "high"] | None = None
    observed_at: datetime | None = None
    evidence_ids: list[str] | None = Field(default=None, max_length=20)


@router.patch("/subjects/{subject_id}/master/items/{item_id}")
async def edit_item(request: Request, subject_id: str, item_id: str, body: EditIn):
    with S(request).sm() as db:
        s, _, role = subject_for(db, request, subject_id, "editor")
        try:
            it = master.edit_item(db, s, item_id, role=role, actor=actor(request), value=body.value, note=body.note, attributes=body.attributes, confidence=body.confidence,
                                  observed_at=body.observed_at, evidence_ids=body.evidence_ids)
        except ProfileError as exc:
            db.commit()
            raise perr(exc) from exc
        db.commit()
        return master.item_dict(db, it, role=role)


class StateIn(Strict):
    to_state: Literal["unassessed", "candidate", "corroborated", "conflicting", "rejected", "not_available"]
    basis: str = Field(min_length=1, max_length=2000)
    evidence_ids: list[str] = Field(default_factory=list, max_length=20)
    independent: bool = False


@router.post("/subjects/{subject_id}/master/items/{item_id}/state")
async def set_state(request: Request, subject_id: str, item_id: str, body: StateIn):
    with S(request).sm() as db:
        s, _, role = subject_for(db, request, subject_id, "editor")
        try:
            it = master.set_state(db, s, item_id, to_state=body.to_state, role=role, actor=actor(request), basis=body.basis, evidence_ids=body.evidence_ids, independent=body.independent)
        except ProfileError as exc:
            db.commit()                                       # a refused corroboration still records the self-attestation
            raise perr(exc) from exc
        db.commit()
        return master.item_dict(db, it, role=role)


@router.delete("/subjects/{subject_id}/master/items/{item_id}")
async def retire_item(request: Request, subject_id: str, item_id: str):
    with S(request).sm() as db:
        s, _, role = subject_for(db, request, subject_id, "editor")
        try:
            master.retire_item(db, s, item_id, role=role, actor=actor(request))
        except ProfileError as exc:
            raise perr(exc) from exc
        db.commit()
        return {"retired": True, "note": "The item is retired, not erased: its history and evidence remain."}


class PromoteIn(Strict):
    basis: str = Field(default="", max_length=900)


@router.post("/subjects/{subject_id}/master/items/{item_id}/use-as-input")
async def promote(request: Request, subject_id: str, item_id: str, body: PromoteIn):
    st = S(request)
    with st.sm() as db:
        s, _, role = subject_for(db, request, subject_id, "editor")
        try:
            it = master.promote_to_input(db, s, item_id, role=role, actor=actor(request), basis=body.basis)
        except ProfileError as exc:
            raise perr(exc) from exc
        db.commit()
        return {**master.item_dict(db, it, role=role), "note": "Now an input. Research still runs only where the authorization covers it."}


class RevealIn(Strict):
    reason: str = Field(min_length=10, max_length=500)


@router.post("/subjects/{subject_id}/master/items/{item_id}/reveal")
async def reveal(request: Request, subject_id: str, item_id: str, body: RevealIn):
    with S(request).sm() as db:
        s, _, role = subject_for(db, request, subject_id, "editor")
        try:
            out = master.reveal(db, s, item_id, role=role, actor=actor(request), reason=body.reason)
        except ProfileError as exc:
            db.commit()
            raise perr(exc) from exc
        db.commit()
        return out


class CompareIn(Strict):
    candidate: str = Field(min_length=1, max_length=64)


@router.post("/subjects/{subject_id}/master/items/{item_id}/compare")
async def compare(request: Request, subject_id: str, item_id: str, body: CompareIn):
    with S(request).sm() as db:
        s, _, role = subject_for(db, request, subject_id, "editor")
        try:
            out = master.verify_reference(db, s, item_id, body.candidate, role=role, actor=actor(request))
        except ProfileError as exc:
            raise perr(exc) from exc
        db.commit()
        return out


class MergeIn(Strict):
    keep_id: str
    merge_ids: list[str] = Field(min_length=1, max_length=20)
    reason: str = Field(min_length=1, max_length=900)


@router.post("/subjects/{subject_id}/master/merge")
async def merge(request: Request, subject_id: str, body: MergeIn):
    with S(request).sm() as db:
        s, _, role = subject_for(db, request, subject_id, "editor")
        try:
            it = master.merge(db, s, body.keep_id, body.merge_ids, role=role, actor=actor(request), reason=body.reason)
        except ProfileError as exc:
            raise perr(exc) from exc
        db.commit()
        return master.item_dict(db, it, role=role)


@router.post("/subjects/{subject_id}/master/items/{item_id}/unmerge")
async def unmerge(request: Request, subject_id: str, item_id: str):
    with S(request).sm() as db:
        s, _, role = subject_for(db, request, subject_id, "editor")
        try:
            it = master.unmerge(db, s, item_id, role=role, actor=actor(request))
        except ProfileError as exc:
            raise perr(exc) from exc
        db.commit()
        return master.item_dict(db, it, role=role)


@router.get("/subjects/{subject_id}/master/export")
async def export(request: Request, subject_id: str):
    """Redacted export: restricted values are omitted, evidence is referenced by id and hash."""
    st = S(request)
    with st.sm() as db:
        s, _, role = subject_for(db, request, subject_id, "editor")
        out = master.export(db, st, s, role=role)
        db.commit()
        return out


@router.get("/subjects/{subject_id}/master/gaps")
async def get_gaps(request: Request, subject_id: str):
    st = S(request)
    with st.sm() as db:
        s, case, role = subject_for(db, request, subject_id, "editor")
        out = gaps.analyze(db, st, s, case, st.adapters, st.settings, role=role)
        db.commit()
        return out


@router.get("/profile/shared-email-providers")
async def shared_providers(request: Request):
    with S(request).sm() as db:
        return {"domains": providers.all_domains(db), "note": "An address at one of these domains says nothing about who owns the domain, so it is never researched as an asset."}


class DomainIn(Strict):
    domain: str = Field(min_length=3, max_length=253)


@router.post("/profile/shared-email-providers", status_code=201, dependencies=[Depends(require_admin)])
async def add_shared_provider(request: Request, body: DomainIn):
    with S(request).sm() as db:
        try:
            doms = providers.add_domain(db, body.domain)
        except ValueError as exc:
            raise ApiError(422, "invalid_domain", str(exc)) from exc
        audit.record(db, "profile.shared_provider_add", actor=actor(request), metadata={"domain": body.domain.lower()[:100]})
        db.commit()
        return {"domains": providers.all_domains(db), "added": body.domain.lower(), "custom": doms}


class ReclassifyIn(Strict):
    to_type: str = Field(min_length=1, max_length=32)
    reason: str = Field(default="", max_length=300)
    preview: bool = False


@router.post("/subjects/{subject_id}/master/items/{item_id}/reclassify")
async def reclassify(request: Request, subject_id: str, item_id: str, body: ReclassifyIn):
    """Change an item's type (and with it its category). With preview=true nothing changes and the effects are listed. The value, evidence and verification state are untouched."""
    with S(request).sm() as db:
        s, _, role = subject_for(db, request, subject_id, "editor")
        try:
            if body.preview:
                return master.preview_reclassify(db, s, item_id, body.to_type)
            it = master.reclassify(db, s, item_id, to_type=body.to_type, role=role, actor=actor(request), reason=body.reason)
        except ProfileError as exc:
            db.commit()
            raise perr(exc) from exc
        db.commit()
        return master.item_dict(db, it, role=role)


@router.post("/subjects/{subject_id}/master/items/{item_id}/reclassify/undo")
async def undo_reclassify(request: Request, subject_id: str, item_id: str):
    with S(request).sm() as db:
        s, _, role = subject_for(db, request, subject_id, "editor")
        try:
            it = master.undo_reclassify(db, s, item_id, role=role, actor=actor(request))
        except ProfileError as exc:
            raise perr(exc) from exc
        db.commit()
        return master.item_dict(db, it, role=role)


@router.get("/subjects/{subject_id}/master/accounting")
async def get_accounting(request: Request, subject_id: str):
    """Per source: returned -> findings -> unique candidate accounts -> profile entries, counted from the stored records."""
    with S(request).sm() as db:
        s, _, _ = subject_for(db, request, subject_id, "editor")
        out = accounting.pipeline(db, s)
        db.commit()
        return out
