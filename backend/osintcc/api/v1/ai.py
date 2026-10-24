"""AI endpoints (spec 11, 23.1.3, 23.8): profiles, per-case policy, preflight, grounded ask, action preview.

Hard rules in this file: AI is OFF unless enabled in settings; local profiles are loopback-only; nothing is sent to a
cloud endpoint without (1) a cloud profile, (2) per-case consent, (3) an approval token bound to the exact payload;
restricted material never goes to the cloud when the case says so; model output can propose but never execute.
"""
from __future__ import annotations

from typing import Any, Literal
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy import select

from ...ai import service as ai
from ...ai.providers import (
    FixtureProvider,
    OllamaProvider,
    OpenAICompatProvider,
    Provider,
    ProviderError,
    ProviderUnavailable,
    is_loopback_url,
)
from ...db.models import AiCall, AiProfile, CaseAiPolicy, Setting
from ...main import ApiError
from ...policy.targets import TargetError
from ...search import service
from ...telemetry import audit
from .routes import S, actor, case_for, require_admin

router: APIRouter = APIRouter()


def ai_enabled(db) -> bool:
    row = db.get(Setting, "ai_enabled")
    return bool(row and row.value_json is True)


def _require_enabled(db) -> None:
    if not ai_enabled(db):
        raise ApiError(503, "ai_disabled", "AI features are off. Enable them in Settings; every other feature works without AI.")


def build_provider(st, p: AiProfile) -> Provider:
    cfg = p.config_json or {}
    factory = getattr(st, "ai_factory", None)
    if factory:  # test/dev seam
        return factory(p)
    key = None
    if cfg.get("secret_name"):
        try:
            import keyring
            key = keyring.get_password("osintcc", cfg["secret_name"])
        except Exception:
            key = None
    if p.provider_type == "fixture":
        return FixtureProvider(p.model_id)
    if p.provider_type == "ollama":
        return OllamaProvider(p.model_id, cfg.get("base_url", "http://127.0.0.1:11434"))
    if p.provider_type == "llamacpp":
        return OpenAICompatProvider(p.model_id, cfg.get("base_url", "http://127.0.0.1:8080"), None, True)
    return OpenAICompatProvider(p.model_id, cfg["base_url"], key, p.local_only)


class ProfileIn(BaseModel):
    name: str = Field(min_length=2, max_length=80, pattern=r"^[A-Za-z0-9 _\-.]+$")
    provider_type: Literal["ollama", "llamacpp", "openai_compat", "fixture"]
    model_id: str = Field(min_length=1, max_length=200)  # any string: users may run any compatible local model
    local_only: bool = True
    base_url: str | None = Field(default=None, max_length=300)
    secret_name: str | None = Field(default=None, pattern=r"^[a-z0-9_\-]{2,40}$")


def _pd(p: AiProfile) -> dict:
    return {"id": p.id, "name": p.name, "provider_type": p.provider_type, "model_id": p.model_id, "local_only": p.local_only,
            "base_url": (p.config_json or {}).get("base_url"), "secret_name": (p.config_json or {}).get("secret_name"),
            "kind": "local" if p.local_only else "cloud"}


@router.get("/ai/profiles")
async def list_profiles(request: Request):
    with S(request).sm() as db:
        return {"ai_enabled": ai_enabled(db), "items": [_pd(p) for p in db.scalars(select(AiProfile))]}


@router.post("/ai/profiles", status_code=201, dependencies=[Depends(require_admin)])
async def create_profile(request: Request, body: ProfileIn):
    st = S(request)
    if body.provider_type in ("ollama", "llamacpp", "fixture") and not body.local_only:
        raise ApiError(422, "invalid_profile", f"{body.provider_type} profiles are always local")
    default = {"ollama": "http://127.0.0.1:11434", "llamacpp": "http://127.0.0.1:8080"}.get(body.provider_type)
    url = body.base_url or default
    if body.provider_type != "fixture":
        if not url:
            raise ApiError(422, "invalid_profile", "base_url is required")
        if body.local_only and not is_loopback_url(url):
            raise ApiError(422, "invalid_profile", "a local profile must use a loopback address (127.0.0.1 / localhost / ::1)")
        if not body.local_only and (urlsplit(url).scheme != "https" or not body.secret_name):
            raise ApiError(422, "invalid_profile", "a cloud profile needs an https base_url and a secret_name (key stored in the OS keyring)")
    with st.sm() as db:
        if db.scalars(select(AiProfile).where(AiProfile.name == body.name)).first():
            raise ApiError(409, "duplicate", "a profile with that name exists")
        p = AiProfile(name=body.name, provider_type=body.provider_type, model_id=body.model_id, local_only=body.local_only,
                      config_json={k: v for k, v in {"base_url": url, "secret_name": body.secret_name}.items() if v})
        db.add(p)
        db.flush()
        audit.record(db, "ai.profile_create", actor=actor(request), resource_id=p.id,
                     metadata={"type": body.provider_type, "local": body.local_only})
        db.commit()
        return _pd(p)


@router.delete("/ai/profiles/{pid}", dependencies=[Depends(require_admin)])
async def delete_profile(request: Request, pid: str):
    with S(request).sm() as db:
        p = db.get(AiProfile, pid)
        if not p:
            raise ApiError(404, "not_found", "profile not found")
        db.delete(p)
        db.commit()
        return {"deleted": pid}


class PolicyIn(BaseModel):
    allow_cloud: bool = False
    require_preview: bool = True
    deny_sensitive_cloud: bool = True


def _policy(db, case_id: str) -> CaseAiPolicy:
    return db.get(CaseAiPolicy, case_id) or CaseAiPolicy(case_id=case_id, allow_cloud=False, require_preview=True, deny_sensitive_cloud=True)


@router.get("/cases/{case_id}/ai-policy")
async def get_policy(request: Request, case_id: str):
    with S(request).sm() as db:
        case_for(db, request, case_id)
        p = _policy(db, case_id)
        return {"case_id": case_id, "allow_cloud": p.allow_cloud, "require_preview": p.require_preview,
                "deny_sensitive_cloud": p.deny_sensitive_cloud}


@router.put("/cases/{case_id}/ai-policy")
async def put_policy(request: Request, case_id: str, body: PolicyIn):
    with S(request).sm() as db:
        case_for(db, request, case_id, "owner")
        db.merge(CaseAiPolicy(case_id=case_id, **body.model_dump()))
        audit.record(db, "ai.policy_update", actor=actor(request), case_id=case_id, metadata=body.model_dump())
        db.commit()
        return {"case_id": case_id, **body.model_dump()}


class PreflightIn(BaseModel):
    profile_id: str
    case_id: str | None = None
    probe: bool = False  # cloud profiles are contacted only when this is true AND the case allows cloud use


@router.post("/ai/preflight")
async def preflight(request: Request, body: PreflightIn):
    """Reports readiness without sending any case content."""
    st = S(request)
    with st.sm() as db:
        p = db.get(AiProfile, body.profile_id)
        if not p:
            raise ApiError(404, "not_found", "profile not found")
        enabled = ai_enabled(db)
        pol = None
        if body.case_id:
            case_for(db, request, body.case_id)
            pol = _policy(db, body.case_id)
    out: dict[str, Any] = {"ai_enabled": enabled, "profile": _pd(p), "content_sent": False}
    if not p.local_only and not (body.probe and pol and pol.allow_cloud):
        h = {"status": "not_probed", "detail": "cloud endpoints are not contacted until you probe explicitly on a case that allows cloud use"}
    else:
        try:
            h = await build_provider(st, p).health()
        except ProviderError as exc:
            h = {"status": "unavailable", "detail": str(exc)}
    out["provider"] = h
    out["model_available"] = p.model_id in h.get("models", []) if h.get("models") is not None else None
    if not p.local_only:
        out["cloud"] = {"case_allows_cloud": bool(pol and pol.allow_cloud), "approval_required_per_request": bool(not pol or pol.require_preview),
                        "sensitive_blocked": bool(not pol or pol.deny_sensitive_cloud),
                        "warning": "Case content would leave this machine for the provider's servers; retention is governed by the provider."}
    out["ready"] = enabled and h.get("status") in ("healthy", "not_probed") and (p.local_only or bool(pol and pol.allow_cloud))         and (p.local_only or h.get("status") == "healthy" or not body.probe)
    return out


class AskIn(BaseModel):
    case_id: str
    profile_id: str
    question: str = Field(min_length=1, max_length=1000)
    include_restricted: bool = False
    transfer_token: str | None = None


@router.post("/ai/ask")
async def ask(request: Request, body: AskIn):
    st = S(request)
    with st.sm() as db:
        _require_enabled(db)
        case_for(db, request, body.case_id, "viewer")
        p = db.get(AiProfile, body.profile_id)
        if not p:
            raise ApiError(404, "not_found", "profile not found")
        pol = _policy(db, body.case_id)
        cloud = not p.local_only
        if cloud and not pol.allow_cloud:
            audit.record(db, "ai.cloud_denied", actor=actor(request), case_id=body.case_id, decision="deny")
            db.commit()
            raise ApiError(403, "cloud_not_allowed", "this case does not allow sending content to a cloud model")
        if cloud and body.include_restricted and pol.deny_sensitive_cloud:
            raise ApiError(403, "sensitive_blocked", "this case forbids sending restricted material to a cloud model")
        chunks, withheld = ai.retrieve(db, body.case_id, body.question, include_restricted=body.include_restricted and (not cloud))
        msgs = ai.build_messages(body.question, chunks)
        sha = ai.payload_hash(msgs)
        used_ids = sorted({e for c in chunks for e in c["evidence_ids"]})
        if cloud:
            token = ai.transfer_token(st.settings.session_token, body.case_id, p.id, sha)
            if pol.require_preview and body.transfer_token != token:
                return {"status": "approval_required", "transfer_token": token, "content_sent": False,
                        "preview": {"provider": (p.config_json or {}).get("base_url"), "model": p.model_id, "chunks": len(chunks),
                                    "evidence_ids": used_ids, "sensitive_items_withheld": withheld,
                                    "approx_tokens": sum(len(m.content) for m in msgs) // 4,
                                    "estimated_cost": "unknown: this app does not know the provider's pricing",
                                    "retention_warning": "Content leaves this machine; the provider's retention and training terms apply.",
                                    "messages": [m.__dict__ for m in msgs]},
                        "how_to_approve": "Repeat the request with this transfer_token. It is valid only for exactly this content."}
        provider = build_provider(st, p)
        call = AiCall(case_id=body.case_id, actor_id=actor(request), provider_type=p.provider_type, model_id=p.model_id,
                      evidence_refs_json=used_ids, cloud_transfer_approved=bool(cloud), payload_sha256=sha, outcome="started")
        db.add(call)
        if cloud:
            audit.record(db, "ai.cloud_transfer", actor=actor(request), case_id=body.case_id, resource_id=call.id,
                         metadata={"host": urlsplit((p.config_json or {}).get("base_url", "")).hostname, "model": p.model_id,
                                   "evidence_items": len(used_ids), "payload_sha256": sha})
        db.commit()
        call_id = call.id
    try:
        raw = await provider.chat(msgs)
    except ProviderUnavailable as exc:
        with st.sm() as db:
            db.get(AiCall, call_id).outcome = "unavailable"
            db.commit()
        raise ApiError(503, "ai_unavailable", f"the model could not be reached: {exc}", True) from exc
    with st.sm() as db:
        verified = ai.verify_answer(raw, chunks, db, body.case_id)
        db.get(AiCall, call_id).outcome = "ok" if verified["structured"] else "unstructured"
        db.commit()
    return {"status": "answered", "ai_call_id": call_id, "provider": p.provider_type, "model": p.model_id, "local": not cloud,
            "sensitive_items_withheld": withheld, "sources_used": [{"kind": c["kind"], "ref": c["ref"], "evidence_ids": c["evidence_ids"]} for c in chunks],
            **verified, "note": "Only statements that cite evidence from this case are listed as verified; inferences are the model's own."}


class ActionIn(BaseModel):
    case_id: str
    type: Literal["search"] = "search"
    target: str = Field(min_length=1, max_length=2048)
    target_type: str | None = None
    adapters: list[str] | None = None


@router.post("/ai/action/preview")
async def action_preview(request: Request, body: ActionIn):
    """Deterministic permission/cost preview of an AI-proposed action. It never starts anything."""
    st = S(request)
    with st.sm() as db:
        _require_enabled(db)
        case = case_for(db, request, body.case_id, "viewer")
        try:
            _, plan = service.preview(db, case, body.target, body.target_type, st.adapters, st.settings, body.adapters, "passive")
        except (TargetError, service.PlanError) as exc:
            raise ApiError(422, "plan_rejected", str(exc)) from exc
    return {**plan, "executed": False, "requires_user_approval": True,
            "how_to_run": "Approve it yourself from the search composer or a collection plan; AI output cannot start collection."}
