"""Provider usage, queue and controls (addendum PQ-1.0).

Reads never contact a provider. The only routes that send a request are the explicit, user-triggered Test, which goes through the same dispatcher (rate limited, accounted for).
No response, here or in the ledger, contains a key, a token or a target identifier.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select

from ...db.models import Case, Job, ProviderLedger, Setting
from ...main import ApiError
from ...quota import PROVIDERS, WAITING_STATUSES
from ...quota.checks import describe, run_check
from ...quota.status import credential_state, four_axes
from ...telemetry import audit
from .routes import S, actor, require_admin

router: APIRouter = APIRouter()


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ConfirmIn(Strict):
    confirm: bool = False
    entitlement_verified: bool = False


def _provider(pid: str):
    if pid not in PROVIDERS:
        raise ApiError(404, "not_found", "unknown provider")
    return PROVIDERS[pid]


def usage_view(st) -> dict[str, Any]:
    items = []
    for e in st.quota.snapshot():
        sec = st.secrets.get(e["credential_name"]) if e["credential_name"] and st.secrets is not None else None
        state = credential_state(e, sec)
        e["state"] = state
        e["axes"] = four_axes(e, state["code"])
        e["test"] = describe(e["provider"])
        items.append(e)
    queued = sum(sum(v for k, v in e["queued"].items() if k in WAITING_STATUSES) for e in items)
    return {"providers": items, "paused": st.quota.is_paused(), "waiting": queued, "enforced": st.quota.enforce,
            "spend_guard": {"paid_spend_usd": 0, "automatic_purchases": False, "automatic_upgrades": False,
                            "text": "Fusion never buys credits, upgrades a plan or enables paid overflow. A used-up quota means the work waits."},
            "note": "Counts are Fusion's own estimate from requests it made. If the same account is used elsewhere, the provider's own headers (when it sends them) take precedence.",
            "timezone": "UTC"}


@router.get("/providers/usage")
async def providers_usage(request: Request):
    return usage_view(S(request))


@router.post("/providers/pause", dependencies=[Depends(require_admin)])
async def pause_all(request: Request):
    st = S(request)
    st.quota.set_paused(True)
    with st.sm() as db:
        audit.record(db, "providers.pause", actor=actor(request))
        db.commit()
    return usage_view(st)


@router.post("/providers/resume", dependencies=[Depends(require_admin)])
async def resume_all(request: Request):
    st = S(request)
    st.quota.set_paused(False)
    with st.sm() as db:
        audit.record(db, "providers.resume", actor=actor(request))
        db.commit()
    return usage_view(st)


@router.post("/providers/{pid}/disable", dependencies=[Depends(require_admin)])
async def disable_provider(request: Request, pid: str):
    _provider(pid)
    st = S(request)
    st.quota.set_disabled(pid, True)
    with st.sm() as db:
        audit.record(db, "providers.disable", actor=actor(request), metadata={"provider": pid})
        db.commit()
    return usage_view(st)


@router.post("/providers/{pid}/enable", dependencies=[Depends(require_admin)])
async def enable_provider(request: Request, pid: str, body: ConfirmIn):
    prov = _provider(pid)
    st = S(request)
    if prov.paid_only and not (body.confirm and body.entitlement_verified):
        raise ApiError(409, "paid_provider", f"{prov.label} is a paid provider. Enable it only after you have checked on the provider's own site that your account includes the capability, "
                       "and confirm both boxes. Fusion never buys anything.")
    st.quota.set_disabled(pid, False)
    with st.sm() as db:
        audit.record(db, "providers.enable", actor=actor(request), metadata={"provider": pid, "paid": prov.paid_only})
        db.commit()
    return usage_view(st)


@router.post("/providers/{pid}/recheck", dependencies=[Depends(require_admin)])
async def recheck_provider(request: Request, pid: str):
    """Forget 'rejected', 'plan restricted' and back-off marks after you changed the key or the plan. Sends nothing."""
    _provider(pid)
    st = S(request)
    st.quota.clear_restrictions(pid)
    with st.sm() as db:
        audit.record(db, "providers.recheck", actor=actor(request), metadata={"provider": pid})
        db.commit()
    return usage_view(st)


@router.post("/providers/{pid}/test", dependencies=[Depends(require_admin)])
async def test_provider(request: Request, pid: str, body: ConfirmIn):
    prov = _provider(pid)
    info = describe(pid)
    st = S(request)
    if info is None:
        return {"state": "unsupported", "detail": f"{prov.label} has no read-only test."}
    if not body.confirm:
        raise ApiError(409, "confirmation_required", f"{info['what']} It uses {info['cost']} and sends the request to {info['url_host']}. Send confirm=true to run it.", False)
    if st.settings.offline:
        raise ApiError(409, "offline", "Offline mode is on; nothing can be sent.")
    from ...quota import GatedHttp
    http = st.runner.ctx_factory().http
    assert isinstance(http, GatedHttp)
    with st.sm() as db:
        contact = db.get(Setting, "edgar_contact")
        contact_v = contact.value_json if contact and isinstance(contact.value_json, str) else None
    secret = st.secrets.get(prov.credential) if prov.credential and st.secrets is not None else None
    out = await run_check(st.quota, http, pid, secret, contact_v)
    with st.sm() as db:
        audit.record(db, "providers.test", actor=actor(request), metadata={"provider": pid, "result": out.get("state"), "http": out.get("http_status")})
        db.commit()
    return {**out, "usage": next((e for e in usage_view(st)["providers"] if e["provider"] == pid), None)}


@router.get("/providers/queue", dependencies=[Depends(require_admin)])
async def provider_queue(request: Request, limit: int = 200):
    """Work that is waiting, running or blocked, with the reason and the earliest time it may run (an estimate)."""
    st = S(request)
    rows = []
    with st.sm() as db:
        titles = {c.id: c.title for c in db.scalars(select(Case))}
        from ...db.models import SearchRun
        for job in db.scalars(select(Job).where(Job.status.in_(("queued", "deferred", "running"))).order_by(Job.priority, Job.created_at).limit(max(1, min(limit, 500)))):
            run = db.get(SearchRun, job.run_id)
            rows.append({"job_id": job.id, "case_id": run.case_id if run else None, "case": titles.get(run.case_id) if run else None, "source": job.adapter_id,
                         "provider": job.provider or None, "operation": job.operation or None, "status": job.quota_status, "attempts": job.attempts, "deferrals": job.deferrals,
                         "priority": job.priority, "enqueued_at": job.created_at, "next_eligible_at": job.next_retry_at,
                         "reason": (job.warnings_json[0][:240] if job.warnings_json and job.quota_status in WAITING_STATUSES else ""), "consumption_known": job.consumption_known})
    return {"items": rows, "paused": st.quota.is_paused(), "note": "Times are estimates of the earliest moment a limit resets, not guarantees."}


@router.get("/providers/ledger", dependencies=[Depends(require_admin)])
async def provider_ledger(request: Request, provider: str | None = None, limit: int = 200):
    """The audit-friendly activity ledger: one row per request that was reserved, with its provider, action, timing and result. It never holds a key or a target."""
    st = S(request)
    with st.sm() as db:
        q = select(ProviderLedger).order_by(ProviderLedger.reserved_at.desc()).limit(max(1, min(limit, 1000)))
        if provider:
            q = q.where(ProviderLedger.provider == provider)
        items = [{"id": r.id, "provider": r.provider, "operation": r.operation, "host": r.url_host, "state": r.state, "http_status": r.http_status, "classification": r.classification,
                  "consumption_known": r.consumption_known, "cost": r.cost, "reserved_at": r.reserved_at, "finished_at": r.finished_at, "job_id": r.job_id, "case_id": r.case_id,
                  "error_code": r.error_code} for r in db.scalars(q)]
    return {"items": items, "note": "Local record of requests Fusion made. It does not contain credentials or the identifiers searched for."}
