"""Runs an approved plan. It re-judges everything at run time (authorization still live, scope unchanged since the plan, approval valid and unused, not offline)
and again before every request inside the adapters. Results become hashed evidence plus typed observations; counts are measured, not estimated.

A run that is interrupted (crash, restart) is marked interrupted and is never replayed: active requests are not idempotent, so a person must plan again.
"""
from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import re
import ssl
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..adapters.active.bounded_ports import check_ports
from ..adapters.active.http_metadata import ScopedHttp
from ..adapters.active.tls_posture import probe_tls
from ..db.models import (
    AivApproval,
    AivObservation,
    AivPlan,
    AivRun,
    AivRunEvent,
    AssetAuthorization,
    Evidence,
)
from ..policy.ssrf import system_resolver
from ..telemetry import audit
from . import parsers, policy, tools
from .plans import preview as plan_preview
from .policy import Budget

_COOKIE_VALUE = re.compile(r"^([^=;\s]+)=[^;]*")


def _now() -> datetime:
    return datetime.now(UTC)


def redact_cookies(cookies: list[str]) -> list[str]:
    """Names and attributes only: a cookie value can be a live session."""
    return [_COOKIE_VALUE.sub(r"\1=<redacted>", c) for c in cookies]


FAMILIES = {"http_metadata": ("http_security_header", "http_cookie", "http_transport", "http_redirect", "http_metadata"), "tls_handshake": ("tls_posture",),
            "tcp_connect": ("tcp_port",), "service_detect": ("tcp_port",), "signature_check": ("signature",)}


class RunRefused(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code, self.message = code, message


class AivExecutor:
    def __init__(self, st: Any, *, resolver: Callable[[str], Awaitable[list[str]]] = system_resolver, ssl_context: ssl.SSLContext | bool = True,
                 transport: Any = None, clock: Callable[[], datetime] = _now):
        self.st, self.resolver, self.ssl_context, self.transport, self.clock = st, resolver, ssl_context, transport, clock
        self.tasks: dict[str, asyncio.Task] = {}
        self.cancel_flags: set[str] = set()
        self.tool_cache: dict[str, Any] = {}
        self.rate_boost = 1.0         # test seam only: multiplies the per-host request rate so lab tests do not sleep; production never changes it

    # ---- approval and start --------------------------------------------------------------------------------------------------------------
    def validate_approval(self, db: Session, plan: AivPlan, approval_id: str) -> AivApproval:
        ap = db.get(AivApproval, approval_id)
        now = self.clock()
        if ap is None or ap.plan_id != plan.id:
            raise RunRefused("approval_missing", "this plan has no such approval; approve the exact plan first")
        if ap.revoked_at is not None:
            raise RunRefused("approval_revoked", "the approval was revoked")
        if ap.plan_hash != plan.plan_hash or ap.plan_version != plan.version:
            raise RunRefused("approval_mismatch", "the plan changed after it was approved; approvals cannot be reused")
        exp = policy.aware(ap.expires_at)
        if exp is None or now >= exp:
            raise RunRefused("approval_expired", "the approval expired")
        if ap.uses >= ap.maximum_uses:
            raise RunRefused("approval_used", "this approval has already been used; approve again for another run")
        return ap

    def recheck(self, db: Session, plan: AivPlan, auth: AssetAuthorization | None, tool_versions: dict[str, str]) -> dict[str, Any]:
        """Plan-time judgement repeated at run time. Raises RunRefused unless every step is still allowed."""
        if auth is None:
            raise RunRefused("auth_missing", "the asset authorization no longer exists")
        if self.st.settings.offline:
            raise RunRefused("offline", "offline mode is on: remote checks are blocked")
        live = policy.authorization_live(auth, self.clock())
        if not live:
            raise RunRefused(live.code, live.reason)
        pv = plan_preview(auth, plan.steps_json, self.clock(), tool_versions=tool_versions, approved_templates=tools.approved_template_ids(db))
        if pv["scope_snapshot_hash"] != plan.projected_limits_json.get("scope_snapshot_hash"):
            raise RunRefused("scope_changed", "the authorization changed after this plan was made; create a new plan")
        if not pv["ok"]:
            first = next((r for r in pv["steps"] if not r["allowed"]), None)
            raise RunRefused(first["code"] if first else "plan_not_ok", first["reason"] if first else "; ".join(pv["problems"]))
        return pv

    async def start(self, db: Session, plan: AivPlan, approval_id: str, actor: str) -> str:
        ap = self.validate_approval(db, plan, approval_id)
        auth = db.get(AssetAuthorization, plan.asset_authorization_id)
        versions = await tools.tool_versions(self.st)
        try:
            self.recheck(db, plan, auth, versions)
        except RunRefused as exc:
            audit.record(db, "aiv.run_refused", actor=actor, case_id=plan.case_id, resource_type="aiv_plan", resource_id=plan.id, decision="deny", metadata={"code": exc.code})
            db.commit()
            raise
        ap.uses += 1                                      # consumed before anything is sent: a crash cannot leave a reusable approval
        run = AivRun(plan_id=plan.id, case_id=plan.case_id, approval_id=ap.id, actor_id=actor, status="queued", scope_snapshot_hash=plan.projected_limits_json.get("scope_snapshot_hash", ""),
                     tool_versions_json=versions)
        db.add(run)
        plan.status = "running"
        db.flush()
        audit.record(db, "aiv.run_start", actor=actor, case_id=plan.case_id, resource_type="aiv_run", resource_id=run.id, metadata={"plan": plan.id, "hash": plan.plan_hash[:12], "steps": len(plan.steps_json)})
        db.commit()
        rid = run.id
        self.tasks[rid] = asyncio.create_task(self._run(rid))
        self.tasks[rid].add_done_callback(lambda _t: self.tasks.pop(rid, None))
        return rid

    def cancel(self, run_id: str) -> bool:
        self.cancel_flags.add(run_id)
        t = self.tasks.get(run_id)
        if t and not t.done():
            t.cancel()
            return True
        return False

    async def wait(self, run_id: str) -> None:
        t = self.tasks.get(run_id)
        if t:
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await t

    def recover(self) -> int:
        """After a restart nothing is resumed. Unfinished runs are marked interrupted and a person must plan again."""
        n = 0
        with self.st.sm() as db:
            for r in db.scalars(select(AivRun).where(AivRun.status.in_(("queued", "running")))):
                r.status, r.finished_at, r.abort_reason = "interrupted", self.clock(), "the application stopped while this run was in progress; it was not resumed"
                plan = db.get(AivPlan, r.plan_id)
                if plan:
                    plan.status = "interrupted"
                self._event(db, r.id, "interrupted", {"reason": r.abort_reason})
                n += 1
            db.commit()
        return n

    # ---- events --------------------------------------------------------------------------------------------------------------------------
    def _event(self, db: Session, run_id: str, kind: str, payload: dict[str, Any]) -> None:
        seq = (db.scalar(select(func.max(AivRunEvent.seq)).where(AivRunEvent.run_id == run_id)) or 0) + 1
        db.add(AivRunEvent(run_id=run_id, seq=seq, kind=kind, payload_json=payload))
        db.flush()

    # ---- the run -------------------------------------------------------------------------------------------------------------------------
    async def _run(self, run_id: str) -> None:
        st = self.st
        with st.sm() as db:
            run = db.get(AivRun, run_id)
            assert run is not None
            plan = db.get(AivPlan, run.plan_id)
            assert plan is not None
            auth = db.get(AssetAuthorization, plan.asset_authorization_id)
            assert auth is not None
            run.status = "running"
            self._event(db, run_id, "started", {"plan_hash": plan.plan_hash, "steps": len(plan.steps_json)})
            db.commit()
            steps, case_id = list(plan.steps_json), plan.case_id
            auth_snapshot = _Snapshot(auth)
        limits = policy.effective_limits(auth_snapshot.limits_json)
        limits["requests_per_second"] = limits["requests_per_second"] * self.rate_boost
        budget = Budget(limits)
        status, reason, ran = "completed", "", 0
        checked: list[list[str]] = []

        def emit(kind: str, payload: dict[str, Any]) -> None:
            with st.sm() as db2:
                self._event(db2, run_id, kind, payload)
                db2.commit()

        try:
            for i, step in enumerate(steps):
                if run_id in self.cancel_flags:
                    status, reason = "cancelled", "cancelled by the operator"
                    break
                try:
                    budget.check_time()
                except policy.BudgetExceeded:
                    status, reason = "partial", "the runtime budget was used up"
                    emit("budget", {"what": "runtime"})
                    break
                # authorization is judged again before every step (it may have been revoked meanwhile)
                with st.sm() as db:
                    fresh = db.get(AssetAuthorization, auth_snapshot.id)
                    live = policy.authorization_live(fresh, self.clock())
                    changed = fresh is not None and policy.scope_snapshot(fresh) != auth_snapshot.scope_hash
                if not live or changed:
                    status, reason = "partial", ("the authorization changed during the run" if changed and live else live.reason)
                    emit("blocked", {"step": i, "code": "auth_changed" if changed else live.code, "reason": reason})
                    break
                emit("step_start", {"step": i, "kind": step["kind"]})
                result, obs, blocked = await self._step(step, auth_snapshot, budget, emit, lambda: run_id in self.cancel_flags)
                ran += 1
                self._persist(run_id, case_id, auth_snapshot, step, result, obs)
                if not blocked or step["kind"] == "tcp_connect":
                    checked += [[_asset_label(step), fam] for fam in FAMILIES[step["kind"]]]
                emit("step_done", {"step": i, "kind": step["kind"], "observations": len(obs), "blocked": blocked})
                if blocked:
                    status = "partial"
                    reason = reason or f"{blocked['code']}: {blocked['reason']}"
        except asyncio.CancelledError:
            status, reason = "cancelled", "cancelled by the operator"
        except policy.BudgetExceeded as exc:
            status, reason = "partial", f"the {exc.what} budget was used up"
        except Exception as exc:                                    # an adapter bug must never take the app down
            status, reason = "failed", f"{type(exc).__name__}"
            emit("error", {"type": type(exc).__name__})
        finally:
            with st.sm() as db:
                run = db.get(AivRun, run_id)
                plan = db.get(AivPlan, run.plan_id) if run else None
                if run:
                    run.status, run.finished_at, run.abort_reason = status, self.clock(), reason[:500]
                    run.actual_request_counts_json = {**budget.counts(), "checked": checked}
                    if plan:
                        plan.status = status if status in ("completed", "failed", "cancelled") else "completed" if status == "partial" else plan.status
                    self._event(db, run_id, "finished", {"status": status, "reason": reason, "counts": budget.counts()})
                    audit.record(db, "aiv.run_finish", actor="system", case_id=run.case_id, resource_type="aiv_run", resource_id=run_id, metadata={"status": status, "requests": budget.requests})
                    db.commit()
            self.cancel_flags.discard(run_id)

    async def _step(self, step: dict[str, Any], auth: Any, budget: Budget, emit: Callable[[str, dict[str, Any]], None], cancelled: Callable[[], bool]
                    ) -> tuple[dict[str, Any], list[parsers.Obs], dict[str, Any] | None]:
        k = step["kind"]
        if k == "http_metadata":
            http = ScopedHttp(auth, budget, resolver=self.resolver, ssl_context=self.ssl_context, transport=self.transport, now=self.clock, emit=emit, cancelled=cancelled)
            res = await http.fetch(step["url"], step["method"], step["follow_redirects"])
            if res.get("blocked") or res.get("error"):
                obs: list[parsers.Obs] = []
                if res.get("error") == "tls_error":
                    obs.append(parsers.Obs("tls_posture", "handshake_failed", "The TLS connection could not be established with certificate verification", "medium",
                                           {"error": res.get("tls_error")}, "Check the certificate chain and host name coverage.", "observed", "medium"))
                if res.get("blocked") and res["blocked"]["code"] == "redirect_out_of_scope":
                    obs.append(parsers.Obs("http_redirect", "redirect_blocked", "A redirect leaves the authorized scope and was NOT followed", "info", {"target": res["blocked"]["reason"][:200]},
                                           "", "observed", "high"))
                return res, obs, res.get("blocked")
            res["set_cookies"] = redact_cookies(res.get("set_cookies") or [])
            obs = parsers.analyze_headers(res.get("headers", {}), scheme=step["url"].split(":", 1)[0], status=res["status"], set_cookies=res["set_cookies"])
            if res.get("redirect_not_followed"):
                obs.append(parsers.Obs("http_redirect", "redirect_seen", "The server redirects; the redirect was not followed", "info", {"location": res["redirect_not_followed"][:300], "status": res["status"]}))
            obs.append(parsers.Obs("http_metadata", "response", f"HTTP {res['status']} from {res.get('final_url', step['url'])}", "info",
                                   {"status": res["status"], "final_url": res.get("final_url"), "server": res.get("headers", {}).get("server"), "content_type": res.get("headers", {}).get("content-type"),
                                    "hops": len(res.get("hops", []))}))
            return res, obs, None
        if k == "tls_handshake":
            res = await probe_tls(auth, step["host"].lower(), step["port"], budget, resolver=self.resolver, trust_context=self.ssl_context if isinstance(self.ssl_context, ssl.SSLContext) else None,
                                  now=self.clock, emit=emit)
            return res, ([] if res.get("blocked") else parsers.analyze_tls(res, self.clock())), res.get("blocked")
        if k == "tcp_connect":
            res = await check_ports(auth, step["host"].lower(), step["ports"], budget, resolver=self.resolver, now=self.clock, emit=emit, cancelled=cancelled)
            blocked = res.get("blocked") or ({"code": "port_skipped", "reason": "; ".join(f"{p}: {r}" for p, r in res["skipped"].items())} if res.get("skipped") else None)
            return res, parsers.port_observations(step["host"], res["ports"]), blocked
        return await tools.run_tool_step(self.st, step, auth, budget, emit, cancelled, self.clock)

    def _persist(self, run_id: str, case_id: str, auth: Any, step: dict[str, Any], result: dict[str, Any], observations: list[parsers.Obs]) -> None:
        raw = json.dumps({"step": step, "result": result}, sort_keys=True, default=str, indent=1).encode()
        sha256, sha512, rel, size = self.st.vault.store(raw)
        asset = _asset_label(step)
        with self.st.sm() as db:
            ev = db.scalars(select(Evidence).where(Evidence.case_id == case_id, Evidence.sha256 == sha256, Evidence.kind == "aiv.step_result")).first()
            if ev is None:
                ev = Evidence(case_id=case_id, kind="aiv.step_result", title=f"AIV {step['kind']} {asset}", sha256=sha256, sha512=sha512, byte_size=size, mime_type="application/json",
                              vault_relpath=rel, retrieved_at=self.clock(), observed_at=self.clock(), capture_method="aiv", sensitivity="INTERNAL", created_by="aiv",
                              description="Raw result of an authorized verification step (cookie values redacted)",
                              chain_of_custody_json=[{"event": "captured", "at": self.clock().isoformat(), "run": run_id, "sha256": sha256}])
                db.add(ev)
                db.flush()
            for o in observations:
                db.add(AivObservation(case_id=case_id, run_id=run_id, asset_authorization_id=auth.id, target_asset=asset[:300], check_type=o.check_type, finding_key=o.key(asset),
                                      observed_value_json={"title": o.title, "rule": o.rule, **o.observed}, severity=o.severity, confidence=o.confidence, basis=o.basis, remediation=o.remediation, evidence_id=ev.id,
                                      observed_at=self.clock()))
            db.commit()


class _Snapshot:
    """A detached copy of the authorization fields a run needs (so the run never holds a session open)."""
    id: Any
    case_id: Any
    asset_type: Any
    canonical_scope: Any
    ports_json: Any
    paths_json: Any
    allowed_classes_json: Any
    exclusions_json: Any
    limits_json: Any
    starts_at: Any
    expires_at: Any
    revoked_at: Any
    retention_terms: Any


    def __init__(self, a: AssetAuthorization):
        for k in ("id", "case_id", "asset_type", "canonical_scope", "ports_json", "paths_json", "allowed_classes_json", "exclusions_json", "limits_json", "starts_at", "expires_at", "revoked_at",
                  "retention_terms"):
            setattr(self, k, getattr(a, k))
        self.scope_hash = policy.scope_snapshot(a)


def _asset_label(step: dict[str, Any]) -> str:
    return host_label(step)


def host_label(step: dict[str, Any]) -> str:
    from .plans import host_of
    h = host_of(step)
    if step["kind"] == "http_metadata":
        return step["url"][:300]
    if step["kind"] == "tls_handshake":
        return f"{h}:{step['port']}"
    return h


def finding_digest(o: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(o, sort_keys=True, default=str).encode()).hexdigest()[:16]
