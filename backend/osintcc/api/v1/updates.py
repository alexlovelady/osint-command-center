"""Update check (spec Phase 5): a user-initiated, signed-manifest comparison. It never downloads or installs anything."""
from __future__ import annotations

import json
import re
from base64 import b64decode
from binascii import Error as B64Error

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import APIRouter, Depends, Request

from ... import __version__
from ...main import ApiError
from ...policy.ssrf import DestinationDenied, SafeHttp
from ...telemetry import audit
from .routes import S, actor, require_admin

router: APIRouter = APIRouter()
_VER = re.compile(r"^\d{1,4}\.\d{1,4}\.\d{1,4}$")
MAX_MANIFEST = 64 * 1024


def _tuple(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in v.split("."))


def verify_manifest(raw: bytes, public_key_hex: str) -> dict:
    """Envelope: {"payload": "<json text>", "signature": "<base64 Ed25519 over the exact payload bytes>"}."""
    try:
        env = json.loads(raw)
        payload, sig = env["payload"].encode(), b64decode(env["signature"], validate=True)
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex)).verify(sig, payload)
        data = json.loads(payload)
    except (InvalidSignature, ValueError, KeyError, TypeError, B64Error, AttributeError) as exc:
        raise ApiError(422, "bad_signature", "the update manifest is malformed or its signature does not match the pinned key") from exc
    if not isinstance(data, dict) or not _VER.match(str(data.get("version", ""))):
        raise ApiError(422, "bad_manifest", "the signed manifest has no valid version")
    return data


@router.post("/updates/check", dependencies=[Depends(require_admin)])
async def check(request: Request):
    st = S(request)
    s = st.settings
    if s.offline:
        raise ApiError(409, "offline", "offline mode is on; no update check was made")
    if not s.update_manifest_url or not s.update_public_key:
        return {"configured": False, "current": __version__,
                "note": "No update source is configured. Updates are never checked automatically and never installed without you."}
    http = st.update_http or SafeHttp(allow_private=s.allow_private_destinations)
    try:
        res = await http.get(s.update_manifest_url)
    except DestinationDenied as exc:
        raise ApiError(403, "policy_denied", str(exc)) from exc
    except Exception as exc:
        raise ApiError(502, "network_error", f"could not fetch the manifest ({type(exc).__name__})") from exc
    if res.status != 200 or len(res.body) > MAX_MANIFEST:
        raise ApiError(502, "bad_response", f"update server answered HTTP {res.status}")
    data = verify_manifest(res.body, s.update_public_key)
    newer = _tuple(str(data["version"])) > _tuple(__version__)
    with st.sm() as db:
        audit.record(db, "update.check", actor=actor(request), metadata={"current": __version__, "latest": data["version"], "signature": "verified"})
        db.commit()
    return {"configured": True, "current": __version__, "latest": data["version"], "update_available": newer, "signature": "verified",
            "released": data.get("released"), "notes": str(data.get("notes", ""))[:2000], "download_url": data.get("url") if newer else None,
            "sha256": data.get("sha256") if newer else None,
            "note": "Nothing was downloaded. If you choose to update, download the file yourself and compare its SHA-256 with the value above."}
