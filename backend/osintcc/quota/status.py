"""Plain-language credential and provider state (addendum section 6).

"Healthy" used to mean "a value exists". These states are kept apart on purpose:
  stored     there is a value in the credential store (nothing more is claimed)
  verified   the provider accepted it on a real call; the time of that call is shown
  rejected   the provider refused it (HTTP 401); Fusion will not retry it until it is replaced
  wrong_format / plan_restricted / quota_exhausted / disabled / not_configured
"""
from __future__ import annotations

from typing import Any

from .catalog import PROVIDERS
from .credentials import censys_kind

LABELS = {
    "not_configured": "Not configured",
    "stored": "Stored (not yet tested)",
    "verified": "Verified by a real call",
    "rejected": "Rejected by the provider",
    "wrong_format": "Wrong format",
    "plan_restricted": "Plan restricted",
    "quota_exhausted": "Quota used up (waiting for reset)",
    "disabled": "Disabled by you",
    "disabled_paid": "Disabled — paid provider",
    "no_key_needed": "No key needed",
}
HINTS = {
    "not_configured": "Add the key in Settings to enable this source. Nothing is sent until you do.",
    "stored": "A value is saved, but Fusion has not yet seen the provider accept it. Use Test to check, or just run an investigation.",
    "verified": "The provider answered a real request made with this credential.",
    "rejected": "The provider said this credential is invalid or revoked. Replace it; Fusion will not keep retrying it.",
    "wrong_format": "The saved value is not the kind of credential this adapter can send. Replace it.",
    "plan_restricted": "The provider says this account's plan does not include the operation Fusion uses.",
    "quota_exhausted": "A limit is used up. Queued work continues by itself when it resets; Fusion never buys more.",
    "disabled": "You turned this provider off. Queued work for it is not sent.",
    "disabled_paid": "Not used because the capability needed is paid. Fusion does not ask you to buy it.",
    "no_key_needed": "This provider needs no key.",
}


def credential_state(entry: dict[str, Any], secret_value: str | None = None) -> dict[str, str]:
    prov = PROVIDERS[entry["provider"]]
    if entry["paid_only"] and entry["disabled"]:
        code = "disabled_paid"
    elif entry["disabled"]:
        code = "disabled"
    elif prov.credential is None and prov.id != "sec_edgar":
        code = "no_key_needed"
    elif prov.credential and not entry["stored"]:
        code = "not_configured"
    elif entry["verified_state"] == "rejected":
        code = "rejected"
    elif entry["verified_state"] == "plan_restricted" or any(o["restricted"] for o in entry["operations"]):
        code = "plan_restricted"
    elif prov.id == "censys" and secret_value is not None and censys_kind(secret_value) == "wrong_format":
        code = "wrong_format"
    elif any(w["remaining"] is not None and w["remaining"] <= 0 for o in entry["operations"] if not o["blocked"] for w in o["windows"]):
        code = "quota_exhausted"
    elif entry["verified_state"] == "verified":
        code = "verified"
    else:
        code = "stored" if prov.credential else "no_key_needed"
    return {"code": code, "label": LABELS[code], "hint": HINTS[code]}


def four_axes(entry: dict[str, Any], state_code: str) -> dict[str, Any]:
    """The four things an operator needs to tell apart. 'unknown' is a real answer: it means Fusion has not seen enough to say."""
    prov = PROVIDERS[entry["provider"]]
    quota = "unknown"
    wins = [w for o in entry["operations"] if not o["blocked"] for w in o["windows"] if w["remaining"] is not None]
    if wins:
        quota = "no" if any(w["remaining"] <= 0 for w in wins) else "yes"
    return {
        "stored_credential": ("not_needed" if prov.credential is None else "yes" if entry["stored"] else "no"),
        "live_authentication": ("yes" if entry["verified_state"] == "verified" else "rejected" if entry["verified_state"] == "rejected" else "not_tested"),
        "endpoint_supported": ("no" if state_code in ("disabled_paid", "plan_restricted") else "yes"),
        "quota_available": quota,
    }
