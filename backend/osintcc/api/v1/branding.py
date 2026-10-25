"""Display-name configuration (addendum v1.1 section 1). Previewable; applying needs an explicit approval flag; identifiers never change."""
from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, ConfigDict, ValidationError

from ... import branding as br
from ...db.models import Setting
from ...main import ApiError
from ...telemetry import audit
from .routes import S, actor, require_admin

router: APIRouter = APIRouter()


def _view(request: Request) -> dict:
    with S(request).sm() as db:
        row = db.get(Setting, "branding")
        preset, b = br.active(row.value_json if row else None)
    return {"active": b.model_dump(), "preset": preset, "presets": {k: {"label": v["label"], "status": v["status"], "branding": v["branding"].model_dump()} for k, v in br.PRESETS.items()},
            "unchanged": br.UNCHANGED, "notice": br.NOTICE}


@router.get("/branding")
async def get_branding(request: Request):
    return _view(request)


class BrandingIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    preset: Literal["current", "fusion", "custom"]
    custom: dict | None = None
    approve_display_change: bool = False
    preview_only: bool = False


@router.put("/branding", dependencies=[Depends(require_admin)])
async def put_branding(request: Request, body: BrandingIn):
    if body.preset == "custom":
        try:
            chosen = br.Branding.model_validate(body.custom or {})
        except ValidationError as exc:
            e = exc.errors()[0]
            raise ApiError(422, "invalid_branding", f"{'.'.join(str(x) for x in e['loc'])}: {e['msg']}") from exc
    else:
        chosen = br.PRESETS[body.preset]["branding"]
    if body.preview_only:
        return {"preview": chosen.model_dump(), "applied": False, "notice": br.NOTICE}
    if not body.approve_display_change:
        raise ApiError(422, "approval_required", "changing the display name needs your explicit approval; it never changes the app identity, data or installer")
    with S(request).sm() as db:
        db.merge(Setting(key="branding", value_json={"preset": body.preset, "branding": chosen.model_dump()}))
        audit.record(db, "branding.change", actor=actor(request), metadata={"preset": body.preset, "name": chosen.productName})
        db.commit()
    return {**_view(request), "applied": True}
