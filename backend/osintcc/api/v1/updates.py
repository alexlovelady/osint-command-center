"""Updates: a user-initiated, signed-manifest check and a verified download. It never installs anything.

* The manifest is a signed envelope `{payload, signature}` (Ed25519). The public key is built into the app
  (`setup/update_key.pub`, override with `OSINTCC_UPDATE_KEY`); it cannot be changed through the API.
* The manifest URL is set by an admin (Settings -> Updates, or `OSINTCC_UPDATE_URL`). A home/LAN update server on a private address is
  allowed because the admin chose it; link-local and unspecified addresses (cloud metadata) are not.
* Download: only from the manifest's own host, no redirects to another host, streamed to disk, SHA-256 verified against the signed manifest, a
  mismatch deletes the file. The result names the file; running it is your decision.
"""
from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import re
import socket
from base64 import b64decode
from binascii import Error as B64Error
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel

from ... import __version__
from ...db.models import Setting
from ...main import ApiError
from ...policy.ssrf import DestinationDenied, SafeHttp
from ...setup.installer import platform_key
from ...telemetry import audit
from .routes import S, actor, require_admin

router: APIRouter = APIRouter()
_VER = re.compile(r"^\d{1,4}\.\d{1,4}\.\d{1,4}$")
MAX_MANIFEST = 64 * 1024
MAX_DOWNLOAD = 2 * 1024 ** 3
SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._ -]{0,120}$")


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


def pick_artifact(data: dict) -> dict | None:
    """The signed per-platform entry for this machine (or the legacy single url/sha256 pair)."""
    plats = data.get("platforms")
    if isinstance(plats, dict):
        e = plats.get(platform_key() or "")
        return e if isinstance(e, dict) and e.get("url") and re.fullmatch(r"[0-9a-f]{64}", str(e.get("sha256", ""))) else None
    if data.get("url") and re.fullmatch(r"[0-9a-f]{64}", str(data.get("sha256", ""))):
        return {"url": data["url"], "sha256": data["sha256"], "name": Path(urlsplit(data["url"]).path).name or "update", "size": data.get("size")}
    return None


def _config(st) -> tuple[str, str]:
    s = st.settings
    url = s.update_manifest_url
    if not url:
        with st.sm() as db:
            row = db.get(Setting, "update_manifest_url")
            url = row.value_json if row and isinstance(row.value_json, str) else ""
    return url.strip(), s.update_public_key.strip()


def _check_target(url: str) -> None:
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ApiError(422, "bad_url", "the update URL must be http(s) with a host")
    try:
        infos = socket.getaddrinfo(parts.hostname, parts.port or (443 if parts.scheme == "https" else 80), proto=socket.IPPROTO_TCP)
    except OSError as exc:
        raise ApiError(502, "dns_failed", f"could not resolve {parts.hostname}") from exc
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_link_local or ip.is_unspecified or ip.is_multicast:
            raise ApiError(403, "policy_denied", "link-local, unspecified and multicast addresses (cloud metadata) are never allowed for updates")


async def _fetch_manifest(st, url: str, key: str) -> dict:
    http = st.update_http or SafeHttp(allow_private=True)
    if st.update_http is None:
        await asyncio.to_thread(_check_target, url)
    try:
        res = await http.get(url)
    except DestinationDenied as exc:
        raise ApiError(403, "policy_denied", str(exc)) from exc
    except Exception as exc:
        raise ApiError(502, "network_error", f"could not fetch the manifest ({type(exc).__name__})") from exc
    if res.status != 200 or len(res.body) > MAX_MANIFEST:
        raise ApiError(502, "bad_response", f"update server answered HTTP {res.status}")
    return verify_manifest(res.body, key)


@router.post("/updates/check", dependencies=[Depends(require_admin)])
async def check(request: Request):
    st = S(request)
    if st.settings.offline:
        raise ApiError(409, "offline", "offline mode is on; no update check was made")
    url, key = _config(st)
    if not url or not key:
        return {"configured": False, "current": __version__,
                "note": "No update server is configured (Settings -> Updates). Updates are never checked automatically and never installed without you."}
    data = await _fetch_manifest(st, url, key)
    newer = _tuple(str(data["version"])) > _tuple(__version__)
    art = pick_artifact(data)
    with st.sm() as db:
        audit.record(db, "update.check", actor=actor(request), metadata={"current": __version__, "latest": data["version"], "signature": "verified"})
        db.commit()
    return {"configured": True, "current": __version__, "latest": data["version"], "update_available": newer, "signature": "verified",
            "released": data.get("released"), "notes": str(data.get("notes", ""))[:2000], "platform": platform_key(),
            "artifact": ({"name": art.get("name"), "size": art.get("size"), "sha256": art["sha256"], "url": art["url"]} if newer and art else None),
            "no_build_for_this_platform": bool(newer and not art),
            "download_url": art["url"] if newer and art else None, "sha256": art["sha256"] if newer and art else None,
            "note": "Nothing was downloaded. Use Download to fetch it with the signed SHA-256 verified, then run it yourself."}


class DownloadIn(BaseModel):
    confirm: bool = False


@router.post("/updates/download", dependencies=[Depends(require_admin)])
async def download(request: Request, body: DownloadIn):
    st = S(request)
    if st.settings.offline:
        raise ApiError(409, "offline", "offline mode is on; nothing was downloaded")
    if not body.confirm:
        raise ApiError(422, "confirmation_required", "send confirm=true to download the update")
    url, key = _config(st)
    if not url or not key:
        raise ApiError(409, "not_configured", "no update server is configured")
    data = await _fetch_manifest(st, url, key)
    if _tuple(str(data["version"])) <= _tuple(__version__):
        raise ApiError(409, "up_to_date", "the signed manifest is not newer than this version")
    art = pick_artifact(data)
    if not art:
        raise ApiError(409, "no_build", "the signed manifest has no build for this platform")
    name = str(art.get("name") or "")
    if not SAFE_NAME.fullmatch(name) or name in (".", ".."):
        raise ApiError(422, "bad_manifest", "the signed manifest names an unsafe file")
    m_host, a_parts = urlsplit(url), urlsplit(str(art["url"]))
    if (a_parts.scheme, a_parts.hostname, a_parts.port) != (m_host.scheme, m_host.hostname, m_host.port):
        raise ApiError(403, "policy_denied", "the update file must be served by the same host as the manifest")
    if st.update_http is None:
        await asyncio.to_thread(_check_target, str(art["url"]))
    dest_dir = st.settings.data_dir / "updates"
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest, tmp = dest_dir / name, dest_dir / (name + ".part")
    h, got = hashlib.sha256(), 0
    try:
        async with httpx.AsyncClient(transport=st.update_transport, timeout=httpx.Timeout(30, read=120), follow_redirects=False, trust_env=False) as c:
            async with c.stream("GET", str(art["url"])) as r:
                if r.status_code != 200:
                    raise ApiError(502, "bad_response", f"update server answered HTTP {r.status_code}")
                with tmp.open("wb") as f:
                    async for chunk in r.aiter_bytes(1 << 20):
                        got += len(chunk)
                        if got > MAX_DOWNLOAD or (art.get("size") and got > int(art["size"]) + 1024):
                            raise ApiError(413, "too_large", "the download is larger than the signed size; aborted")
                        h.update(chunk)
                        f.write(chunk)
        if h.hexdigest() != art["sha256"]:
            raise ApiError(422, "hash_mismatch", "the downloaded file does not match the signed SHA-256; it was deleted")
        tmp.replace(dest)
    except ApiError:
        tmp.unlink(missing_ok=True)
        raise
    except httpx.HTTPError as exc:
        tmp.unlink(missing_ok=True)
        raise ApiError(502, "network_error", f"download failed ({type(exc).__name__})") from exc
    with st.sm() as db:
        audit.record(db, "update.download", actor=actor(request), metadata={"version": data["version"], "file": name, "sha256": art["sha256"], "bytes": got})
        db.commit()
    return {"version": data["version"], "file": str(dest), "sha256": art["sha256"], "bytes": got, "verified": True,
            "downloaded_at": datetime.now(UTC).isoformat(timespec="seconds"),
            "next": "Close the app, then run this file yourself. The app does not install updates. Back up first (Settings -> Encryption & backup)."}
