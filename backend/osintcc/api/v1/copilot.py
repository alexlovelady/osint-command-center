"""AI Copilot & Tutor API.

Streaming chat is NDJSON (one JSON event per line). Approving a proposal is a separate request by the signed-in person; the model has no path to it.
"""
from __future__ import annotations

import json
from typing import Any, Literal

from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import select

from ...copilot import context as cx
from ...copilot import store
from ...copilot.engine import ChatRequest, Engine, suggested_prompts
from ...copilot.kb import KnowledgeBase, static_chunks, tool_chunks
from ...copilot.tools import Toolbox, ToolRefused, case_access, proposal_dict
from ...db.models import AiProfile, CopilotConversation, CopilotProposal, Setting
from ...main import ApiError
from ...telemetry import audit
from .routes import S, actor, require_admin

router: APIRouter = APIRouter()


async def _kb(st) -> tuple[KnowledgeBase, dict[str, dict[str, Any]]]:
    tools = await cx.tool_status(st)
    return KnowledgeBase(tool_chunks(st.adapters, tools)), tools


@router.get("/copilot/status")
async def status(request: Request, profile_id: str | None = None):
    return await Engine(S(request), actor(request)).status(profile_id)


@router.get("/copilot/suggestions")
async def suggestions(request: Request, mode: str = "general", route: str = "overview", tab: str | None = None, case_id: str | None = None):
    ctx = cx.clean_ctx({"route": route, "tab": tab, "case_id": case_id})
    return {"items": suggested_prompts(mode if mode in store.MODES else "general", ctx, bool(case_id))}


class SettingsIn(BaseModel):
    profile_id: str | None = None
    context_chars: int | None = Field(default=None, ge=2000, le=200000)


@router.put("/copilot/settings", dependencies=[Depends(require_admin)])
async def put_settings(request: Request, body: SettingsIn):
    st = S(request)
    with st.sm() as db:
        if body.profile_id is not None:
            if body.profile_id and not db.get(AiProfile, body.profile_id):
                raise ApiError(404, "not_found", "profile not found")
            db.merge(Setting(key="copilot_profile_id", value_json=body.profile_id))
        if body.context_chars is not None:
            db.merge(Setting(key="copilot_context_chars", value_json=body.context_chars))
        audit.record(db, "copilot.settings", actor=actor(request), metadata=body.model_dump(exclude_none=True))
        db.commit()
    return await status(request)


# ---------------------------------------------------------------------------------------------------- conversations
@router.get("/copilot/conversations")
async def conversations(request: Request, case_id: str | None = None, scope: Literal["case", "general", "all"] = "all"):
    with S(request).sm() as db:
        if case_id:
            try:
                case_access(db, actor(request), case_id)
            except ToolRefused as exc:
                raise ApiError(404, "not_found", str(exc)) from exc
        which: Any = False if scope == "all" and not case_id else (case_id if case_id else None)
        return {"items": store.list_conversations(db, actor(request), which)}


class NewConv(BaseModel):
    case_id: str | None = None
    mode: Literal["general", "investigation", "tutor"] = "general"


@router.post("/copilot/conversations", status_code=201)
async def new_conversation(request: Request, body: NewConv):
    with S(request).sm() as db:
        if body.case_id:
            try:
                case_access(db, actor(request), body.case_id)
            except ToolRefused as exc:
                raise ApiError(404, "not_found", str(exc)) from exc
        c = store.new_conversation(db, actor(request), body.case_id, body.mode)
        db.commit()
        return store.conversation_dict(c)


@router.get("/copilot/conversation")
async def current_conversation(request: Request, case_id: str | None = None, conversation_id: str | None = None):
    """The conversation for this investigation (or the general one) with its messages and proposals. Damaged rows are skipped and counted."""
    with S(request).sm() as db:
        if case_id:
            try:
                case_access(db, actor(request), case_id)
            except ToolRefused as exc:
                raise ApiError(404, "not_found", str(exc)) from exc
        c = store.get_conversation(db, actor(request), case_id, conversation_id, create=False)
        if conversation_id and c is None:
            raise ApiError(404, "not_found", "conversation not found")
        if c is None:
            return {"conversation": None, "messages": [], "proposals": [], "skipped_corrupt": 0}
        msgs, skipped = store.load_messages(db, c.id)
        props = [proposal_dict(p) for p in db.scalars(select(CopilotProposal).where(CopilotProposal.conversation_id == c.id).order_by(CopilotProposal.created_at))]
        return {"conversation": store.conversation_dict(c), "messages": msgs, "proposals": props, "skipped_corrupt": skipped}


@router.delete("/copilot/conversations/{cid}")
async def delete_conversation(request: Request, cid: str):
    with S(request).sm() as db:
        c = db.get(CopilotConversation, cid)
        if not c or c.user_id != actor(request):
            raise ApiError(404, "not_found", "conversation not found")
        audit.record(db, "copilot.conversation_delete", actor=actor(request), case_id=c.case_id, resource_id=cid)
        db.delete(c)
        db.commit()
    return {"deleted": cid}


# --------------------------------------------------------------------------------------------------------- chat
class ChatIn(BaseModel):
    text: str = Field(min_length=1, max_length=2000)
    mode: Literal["general", "investigation", "tutor"] = "general"
    ctx: dict[str, Any] = Field(default_factory=dict)
    conversation_id: str | None = None
    profile_id: str | None = None
    level: Literal["beginner", "advanced"] = "beginner"
    include_restricted: bool = False
    transfer_token: str | None = None
    intent_hint: Literal["next_steps"] | None = None
    quick: bool = False


@router.post("/copilot/chat")
async def chat(request: Request, body: ChatIn):
    st, user = S(request), actor(request)
    eng = Engine(st, user)
    req = ChatRequest(**body.model_dump())

    async def gen():
        try:
            async for e in eng.chat(req):
                yield json.dumps(e, default=str) + "\n"
        except Exception as exc:    # the stream must end with a clear event, never a broken connection
            yield json.dumps({"type": "error", "code": "copilot_failed", "message": f"The Copilot hit an internal error ({type(exc).__name__}). Nothing was changed."}) + "\n"
    return StreamingResponse(gen(), media_type="application/x-ndjson", headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})


class NextIn(BaseModel):
    case_id: str
    include_restricted: bool = False


@router.post("/copilot/next-steps")
async def next_steps(request: Request, body: NextIn):
    """Prioritised recommendations computed from the case's stored data. Deterministic: works with no model."""
    st = S(request)
    with st.sm() as db:
        try:
            case_access(db, actor(request), body.case_id)
        except ToolRefused as exc:
            raise ApiError(404, "not_found", str(exc)) from exc
        tools = await cx.tool_status(st)
        steps = cx.next_steps(st, db, tools, body.case_id, body.include_restricted)
    return {"steps": steps, "basis": "rules over counts and statuses stored in this case; no model was used and nothing was run"}


# ------------------------------------------------------------------------------------------------------ proposals
class ApproveIn(BaseModel):
    confirm: bool = False
    confirmed_adapters: list[str] = Field(default_factory=list)


def _note(db, p: CopilotProposal, user: str, text: str, meta: dict[str, Any]) -> None:
    conv = db.get(CopilotConversation, p.conversation_id)
    if conv:
        store.add_message(db, conv, "note", text, conv.mode, {"proposal": p.id, **meta})


@router.post("/copilot/proposals/{pid}/approve")
async def approve(request: Request, pid: str, body: ApproveIn):
    st, user = S(request), actor(request)
    if not body.confirm:
        raise ApiError(422, "confirmation_required", "send confirm=true to approve this proposal")
    with st.sm() as db:
        p = db.get(CopilotProposal, pid)
        conv = db.get(CopilotConversation, p.conversation_id) if p else None
        if not p or not conv or conv.user_id != user:
            raise ApiError(404, "not_found", "proposal not found")
        tool, case_id = p.tool, p.case_id
        # Sources that need explicit confirmation must be among the ones the person ticked; they cannot be added by the client afterwards.
        needed = set((p.preview_json or {}).get("needs_confirmation", []))
        extra = set(body.confirmed_adapters) - set((p.args_json or {}).get("adapters", []))
        if extra:
            raise ApiError(422, "invalid", "confirmed_adapters may only name sources in the proposal")
        if needed - set(body.confirmed_adapters):
            raise ApiError(422, "confirmation_required", f"tick the confirmation for: {', '.join(sorted(needed - set(body.confirmed_adapters)))}")
    kb, _ = await _kb(st)
    box = Toolbox(st, user, kb, case_id)
    try:
        result = await box.execute(pid, body.confirmed_adapters)
    except ToolRefused as exc:
        with st.sm() as db:
            p = db.get(CopilotProposal, pid)
            if p:
                _note(db, p, user, f"You approved '{tool}' but it was refused and nothing was done: {exc}", {"status": "failed"})
                db.commit()
        raise ApiError(409, "policy_denied", str(exc)) from exc
    with st.sm() as db:
        p = db.get(CopilotProposal, pid)
        assert p is not None
        _note(db, p, user, f"You approved '{tool}'. It was executed. Result: {json.dumps(result, default=str)[:600]}", {"status": "executed", "result": result})
        db.commit()
        return {"proposal": proposal_dict(p), "result": result}


@router.post("/copilot/proposals/{pid}/reject")
async def reject(request: Request, pid: str):
    st, user = S(request), actor(request)
    with st.sm() as db:
        p = db.get(CopilotProposal, pid)
        conv = db.get(CopilotConversation, p.conversation_id) if p else None
        if not p or not conv or conv.user_id != user:
            raise ApiError(404, "not_found", "proposal not found")
        tool, case_id = p.tool, p.case_id
    kb, _ = await _kb(st)
    try:
        Toolbox(st, user, kb, case_id).reject(pid)
    except ToolRefused as exc:
        raise ApiError(409, "already_decided", str(exc)) from exc
    with st.sm() as db:
        p = db.get(CopilotProposal, pid)
        assert p is not None
        _note(db, p, user, f"You rejected '{tool}'. Nothing was done.", {"status": "rejected"})
        db.commit()
        return {"proposal": proposal_dict(p)}


# ------------------------------------------------------------------------------------------------- docs & tutorials
@router.get("/copilot/docs/search")
async def docs_search(request: Request, q: str, kinds: str | None = None, limit: int = 8):
    kb, _ = await _kb(S(request))
    kset = {k for k in (kinds or "").split(",") if k} or None
    hits = kb.search(q[:300], min(max(limit, 1), 20), kset)
    return {"supported": kb.supported(hits), "items": [{"id": h.chunk.id, "kind": h.chunk.kind, "title": h.chunk.title, "source": h.chunk.source,
                                                       "text": h.chunk.text[:700], "score": round(h.score, 2), "where": h.chunk.meta.get("where")} for h in hits]}


@router.get("/copilot/docs/{chunk_id:path}")
async def docs_get(request: Request, chunk_id: str):
    kb, _ = await _kb(S(request))
    c = kb.get(chunk_id)
    if not c:
        raise ApiError(404, "not_found", "no such documentation entry")
    return {"id": c.id, "kind": c.kind, "title": c.title, "source": c.source, "text": c.text, "meta": {k: v for k, v in c.meta.items() if k != "manifest"}}


@router.get("/copilot/tutorials")
async def tutorials(request: Request):
    return {"items": [{"id": c.id.split(":", 1)[1], "title": c.title, "steps": len(c.meta["steps"]), "module": c.meta.get("module")}
                      for c in static_chunks() if c.kind == "tutorial"]}


@router.get("/copilot/tutorials/{tid}")
async def tutorial(request: Request, tid: str, level: Literal["beginner", "advanced"] = "beginner"):
    for c in static_chunks():
        if c.id == f"tutorial:{tid}":
            steps = [{"n": i, "go": s["go"], "target": s.get("target"), "text": s.get(level) or s["beginner"]} for i, s in enumerate(c.meta["steps"], 1)]
            return {"id": tid, "title": c.title, "level": level, "steps": steps}
    raise ApiError(404, "not_found", "no such tutorial")
