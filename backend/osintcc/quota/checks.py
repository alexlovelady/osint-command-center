"""User-triggered, read-only provider checks ("Test"). Each is one ordinary request that goes through the same dispatcher as everything else, so it is rate limited,
accounted for in the ledger and counted against the provider's quota. Nothing here is automatic and nothing here submits, scans or uploads.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

from ..db.models import ProviderState
from .catalog import FIXED_DAY, FIXED_HOUR, FIXED_MINUTE, PROVIDERS
from .gate import GatedHttp, JobScope, current_scope
from .service import QuotaService, _iso

# what each check calls, why that endpoint was chosen, and what it costs
CHECKS: dict[str, dict[str, Any]] = {
    "virustotal": {"url": "https://www.virustotal.com/api/v3/domains/example.com", "headers": lambda k: {"x-apikey": k}, "cost": "1 request of the daily quota",
                   "what": "Looks up the reserved domain example.com."},
    "urlscan": {"url": "https://urlscan.io/api/v1/quotas", "headers": lambda k: {"API-Key": k} if k else {}, "cost": "no scan quota",
                "what": "Reads your account's own quota table, which also lets Fusion use your real limits."},
    "censys": {"url": "https://api.platform.censys.io/v3/global/asset/host/8.8.8.8", "headers": None, "cost": "1 of your 100 monthly credits",
               "what": "Looks up one well-known public address (8.8.8.8)."},
    "brave": {"url": "https://api.search.brave.com/res/v1/web/search?q=example&count=1", "headers": lambda k: {"X-Subscription-Token": k, "Accept": "application/json"},
              "cost": "1 search request", "what": "Runs one search for the word example; the response headers reveal your plan's limits."},
    "sec_edgar": {"url": "https://data.sec.gov/submissions/CIK0000320193.json", "headers": None, "cost": "1 request at the SEC's fair-access pace",
                  "what": "Fetches one public company record using your contact as the User-Agent."},
}


def describe(provider: str) -> dict[str, str] | None:
    c = CHECKS.get(provider)
    return {"what": c["what"], "cost": c["cost"], "url_host": c["url"].split("/")[2]} if c else None


async def run_check(quota: QuotaService, http: GatedHttp, provider: str, secret: str | None, contact: str | None, case_id: str | None = None) -> dict[str, Any]:
    spec = CHECKS.get(provider)
    prov = PROVIDERS[provider]
    if spec is None:
        return {"state": "unsupported", "detail": f"{prov.label} has no read-only test. It is verified the first time a real investigation uses it."}
    if prov.credential and not secret:
        return {"state": "not_configured", "detail": "There is no stored credential to test."}
    if provider == "sec_edgar":
        from .credentials import validate_contact
        err, contact_n = validate_contact(contact)
        if err:
            return {"state": "wrong_format", "detail": err}
        headers = {"User-Agent": contact_n, "Accept": "application/json"}
    elif provider == "censys":
        from .credentials import censys_kind
        kind = censys_kind(secret)
        if kind != "pat":
            return {"state": "wrong_format", "detail": "The test uses the Platform API, which needs a Personal Access Token. A legacy API_ID:API_SECRET cannot be tested there."}
        headers = {"Authorization": f"Bearer {secret}", "Accept": "application/vnd.censys.api.v3.host.v1+json"}
    else:
        headers = spec["headers"](secret)
    scope = JobScope(case_id=case_id)
    token = current_scope.set(scope)
    try:
        res = await http.get(spec["url"], headers=headers)
    except Exception as exc:
        return {"state": "unreachable", "detail": f"The provider could not be reached ({type(exc).__name__}). Nothing about the credential is known.", "http_status": None}
    finally:
        current_scope.reset(token)
    if scope.denials:
        d = scope.denials[0]
        return {"state": d.status, "detail": d.reason, "eligible_at": _iso(d.eligible_at), "http_status": None}
    out = scope.outcomes[-1] if scope.outcomes else None
    if provider == "urlscan" and res.status == 200:
        _learn_urlscan(quota, res.body)
    if provider == "sec_edgar" and res.status == 403:
        return {"state": "rejected", "detail": "The SEC refused the request. Check that your contact is a real name and email.", "http_status": 403}
    if out is None:
        return {"state": "unknown", "detail": f"HTTP {res.status}", "http_status": res.status}
    state = {"ok": "verified", "no_record": "verified", "rejected_credentials": "rejected", "plan_restricted": "plan_restricted", "insufficient_credits": "quota_exhausted",
             "rate_limited": "quota_exhausted", "server_error": "unreachable"}.get(out.classification, "unknown")
    detail = {"verified": "The provider accepted the request.", "rejected": out.reason, "plan_restricted": out.reason, "quota_exhausted": out.reason or "A limit is used up.",
              "unreachable": out.reason or "The provider had a problem."}.get(state, f"HTTP {res.status}")
    return {"state": state, "detail": detail, "http_status": res.status, "eligible_at": _iso(out.eligible_at)}


def _learn_urlscan(quota: QuotaService, body: bytes) -> None:
    """Fold the account's own quota table into the dispatcher's limits (replacing the defaults for those windows)."""
    try:
        limits = json.loads(body)["limits"]
    except (ValueError, KeyError, TypeError):
        return
    op_for = {"public": "scan_public", "unlisted": "scan_unlisted", "private": "scan_private", "search": "search", "retrieve": "result"}
    prov = PROVIDERS["urlscan"]
    now = quota.now()
    ends = {"minute": (FIXED_MINUTE, now.replace(second=0, microsecond=0) + timedelta(minutes=1)), "hour": (FIXED_HOUR, now.replace(minute=0, second=0, microsecond=0) + timedelta(hours=1)),
            "day": (FIXED_DAY, now.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1))}
    with quota.sm() as db, quota._lock:
        acct = quota.account_key(prov)
        st = db.get(ProviderState, ("urlscan", acct)) or ProviderState(provider="urlscan", account_key=acct, learned_json={}, blocked_status="", disabled=False, disabled_reason="",
                                                                       verified_state="", last_error="", updated_at=now)
        db.add(st)
        ops = dict((st.learned_json or {}).get("ops") or {})
        for action, windows in limits.items():
            op = op_for.get(action)
            if op is None or not isinstance(windows, dict):
                continue
            cur = {e["wid"]: e for e in ops.get(op, []) if isinstance(e, dict)}
            for win, vals in windows.items():
                if win not in ends or not isinstance(vals, dict) or "limit" not in vals:
                    continue
                wid, reset = ends[win]
                cur[wid] = {"wid": wid, "limit": float(vals["limit"]), "remaining": float(vals["remaining"] if vals.get("remaining") is not None else vals["limit"]), "reset_at": reset.isoformat(),
                            "observed_at": datetime.now(UTC).isoformat(), "seconds": 0}
            ops[op] = list(cur.values())
        st.learned_json = {**(st.learned_json or {}), "ops": ops}
        db.commit()

