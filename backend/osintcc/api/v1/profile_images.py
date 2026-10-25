"""Image workbench API (addendum TP-1.0 section 5). Import, metadata, local duplicate matching, manual reverse-search bookkeeping.

There is no route that identifies a person, compares faces or calls a reverse-image provider.
"""
from __future__ import annotations

import os
import re
import tempfile
from typing import Literal

from fastapi import APIRouter, Query, Request
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from ...db.models import Evidence, ImageAsset, ImageMatch
from ...evidence.vault import VaultError, VaultLocked
from ...main import ApiError
from ...profile import consent, images
from ...profile.service import ProfileError
from ...telemetry import audit
from .profile import perr, subject_for
from .routes import S, actor

router: APIRouter = APIRouter()


def _asset(db, subject_id: str, image_id: str) -> ImageAsset:
    a = db.get(ImageAsset, image_id)
    if not a or a.subject_id != subject_id:
        raise ApiError(404, "not_found", "image not found")
    return a


@router.post("/subjects/{subject_id}/images", status_code=201)
async def import_image(request: Request, subject_id: str, filename: str = Query(min_length=1, max_length=255),
                       ownership: Literal["user_owned", "public", "authorized"] = "user_owned", source_url: str | None = Query(default=None, max_length=2000),
                       confirm_rights: bool = False):
    st = S(request)
    if not confirm_rights:
        raise ApiError(422, "rights_required", "confirm the image is yours, public, or provided with documented authorization")
    with st.sm() as db:
        subject_for(db, request, subject_id, "editor")
    size, tmp = 0, tempfile.SpooledTemporaryFile(max_size=8 * 1024 * 1024)
    try:
        async for chunk in request.stream():
            size += len(chunk)
            if size > images.MAX_BYTES:
                raise ApiError(413, "too_large", f"images are limited to {images.MAX_BYTES // (1024 * 1024)} MB")
            tmp.write(chunk)
        tmp.seek(0)
        data = tmp.read()
    finally:
        tmp.close()
    with st.sm() as db:
        s, case, role = subject_for(db, request, subject_id, "editor")
        try:
            asset, created = images.import_image(db, st.vault, s, data, os.path.basename(re.sub(r"\\", "/", filename)), ownership=ownership, source_url=source_url, actor=actor(request))
        except ProfileError as exc:
            audit.record(db, "image.refused", actor=actor(request), case_id=case.id, resource_type="subject", resource_id=s.id, decision="deny", metadata={"code": exc.code})
            db.commit()
            raise ApiError(422 if not exc.code.startswith("consent_") and exc.code != "out_of_scope" else 403, exc.code, exc.message) from exc
        except VaultLocked as exc:
            raise ApiError(503, "vault_locked", str(exc), True) from exc
        except VaultError as exc:
            raise ApiError(413, "too_large", str(exc)) from exc
        db.commit()
        return {**images.asset_dict(asset, role=role), "created": created}


@router.get("/subjects/{subject_id}/images")
async def list_images(request: Request, subject_id: str):
    with S(request).sm() as db:
        s, _, role = subject_for(db, request, subject_id)
        rows = db.scalars(select(ImageAsset).where(ImageAsset.subject_id == s.id).order_by(ImageAsset.created_at)).all()
        counts = dict(db.execute(select(ImageMatch.asset_id, func.count()).where(ImageMatch.subject_id == s.id, ImageMatch.review_state == "candidate").group_by(ImageMatch.asset_id)).all())
        return {"total": len(rows), "limits": images.LIMITS, "items": [{**images.asset_dict(a, role=role), "unreviewed_matches": counts.get(a.id, 0)} for a in rows]}


@router.get("/subjects/{subject_id}/images/{image_id}")
async def get_image(request: Request, subject_id: str, image_id: str):
    with S(request).sm() as db:
        s, case, role = subject_for(db, request, subject_id)
        a = _asset(db, s.id, image_id)
        if a.has_gps and role in ("owner", "editor"):
            audit.record(db, "image.gps_view", actor=actor(request), case_id=case.id, resource_type="image_asset", resource_id=a.id)
            db.commit()
        return images.asset_dict(a, role=role)


@router.get("/subjects/{subject_id}/images/{image_id}/thumbnail")
async def thumbnail(request: Request, subject_id: str, image_id: str):
    """A pixel-only re-encoded PNG. The original bytes are never served to the browser."""
    st = S(request)
    with st.sm() as db:
        s, _, _ = subject_for(db, request, subject_id)
        a = _asset(db, s.id, image_id)
        ev = db.get(Evidence, a.evidence_id)
        assert ev is not None and ev.vault_relpath
        rel, sha = ev.vault_relpath, ev.sha256
    try:
        data = st.vault.read(rel, sha)
        png = images.sanitized_png(data)
    except ProfileError as exc:
        raise ApiError(422, exc.code, exc.message) from exc
    except VaultLocked as exc:
        raise ApiError(503, "vault_locked", str(exc), True) from exc
    return Response(content=png, media_type="image/png", headers={"Content-Disposition": "inline; filename=preview.png"})


@router.get("/subjects/{subject_id}/images/{image_id}/matches")
async def list_matches(request: Request, subject_id: str, image_id: str):
    with S(request).sm() as db:
        s, _, _ = subject_for(db, request, subject_id)
        a = _asset(db, s.id, image_id)
        rows = db.scalars(select(ImageMatch).where(ImageMatch.asset_id == a.id).order_by(ImageMatch.observed_at)).all()
        reverse = db.scalars(select(ImageMatch).where(ImageMatch.other_asset_id == a.id)).all()      # pairs found from the other image's side
        return {"total": len(rows) + len(reverse), "limits": images.LIMITS, "items": [images.match_dict(db, m) for m in [*rows, *reverse]]}


class RematchIn(BaseModel):
    phash_max: int = Field(default=images.DEFAULT_THRESHOLDS["phash_max"], ge=0, le=20)
    dhash_max: int = Field(default=images.DEFAULT_THRESHOLDS["dhash_max"], ge=0, le=24)
    crop_max: int = Field(default=images.DEFAULT_THRESHOLDS["crop_max"], ge=0, le=16)


@router.post("/subjects/{subject_id}/images/{image_id}/rematch")
async def rematch(request: Request, subject_id: str, image_id: str, body: RematchIn):
    with S(request).sm() as db:
        s, _, _ = subject_for(db, request, subject_id, "editor")
        a = _asset(db, s.id, image_id)
        made = images.match_local(db, a, body.model_dump())
        db.commit()
        return {"new_matches": len(made), "thresholds": body.model_dump(), "limits": images.LIMITS}


class ReviewIn(BaseModel):
    match_id: str
    state: Literal["candidate", "confirmed_same_image", "rejected", "unsure"]
    note: str = Field(min_length=1, max_length=800)


@router.post("/subjects/{subject_id}/images/{image_id}/review")
async def review(request: Request, subject_id: str, image_id: str, body: ReviewIn):
    with S(request).sm() as db:
        s, _, _ = subject_for(db, request, subject_id, "editor")
        _asset(db, s.id, image_id)
        try:
            m = images.review_match(db, s, body.match_id, state=body.state, reviewer=actor(request), note=body.note)
        except ProfileError as exc:
            raise perr(exc) from exc
        db.commit()
        return images.match_dict(db, m)


@router.get("/subjects/{subject_id}/images/{image_id}/reverse-search")
async def reverse_search(request: Request, subject_id: str, image_id: str):
    with S(request).sm() as db:
        s, _, _ = subject_for(db, request, subject_id, "editor")
        a = _asset(db, s.id, image_id)
        d = consent.check(db, s, "reverse_image")
        guide = images.reverse_search_guide(a)
        guide["authorization"] = {"allowed": d.allowed, "reason": d.reason}
        if not d.allowed:
            for p in guide["providers"]:
                p["link"] = None            # no link-out without live, sufficiently verified authorization
        return guide


class ProviderResultIn(BaseModel):
    provider: Literal["google_lens", "bing_visual", "tineye", "other"]
    matched_url: str = Field(min_length=8, max_length=2000)
    note: str = Field(default="", max_length=1000)
    screenshot_evidence_id: str | None = None


@router.post("/subjects/{subject_id}/images/{image_id}/matches", status_code=201)
async def add_provider_result(request: Request, subject_id: str, image_id: str, body: ProviderResultIn):
    """Records a result a person found by hand. The application did not run the search and makes no claim that a provider was queried."""
    with S(request).sm() as db:
        s, _, _ = subject_for(db, request, subject_id, "editor")
        a = _asset(db, s.id, image_id)
        try:
            consent.require(db, s, "reverse_image")
            m = images.record_provider_result(db, a, provider=body.provider, matched_url=body.matched_url, note=body.note, actor=actor(request),
                                              screenshot_evidence_id=body.screenshot_evidence_id)
        except ProfileError as exc:
            raise perr(exc) from exc
        db.commit()
        return images.match_dict(db, m)
