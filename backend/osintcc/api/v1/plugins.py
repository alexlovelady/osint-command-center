"""Plugin management endpoints (spec 7, 23.7, 23.8)."""
from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field

from ...main import ApiError
from ...plugins import PluginError, PluginManifest, run_contract_tests, tree_hash
from ...plugins.manager import PluginManager
from .routes import S, actor, require_admin

router: APIRouter = APIRouter()


def mgr(request: Request) -> PluginManager:
    st = S(request)
    if not hasattr(st, "plugin_manager") or st.plugin_manager is None:
        st.plugin_manager = PluginManager(st)
    return st.plugin_manager


@router.get("/plugins")
async def list_plugins(request: Request):
    return {"items": mgr(request).list(), "note": "External plugins are OFF until a person enables them with the reviewed hash."}


class InstallIn(BaseModel):
    path: str = Field(min_length=1, max_length=500)


@router.post("/plugins/install", status_code=201, dependencies=[Depends(require_admin)])
async def install(request: Request, body: InstallIn):
    try:
        return mgr(request).install(Path(body.path), actor(request))
    except PluginError as exc:
        raise ApiError(422, "invalid_plugin", str(exc)) from exc


class EnableIn(BaseModel):
    accept_hash: str = Field(min_length=64, max_length=64)


@router.post("/plugins/{pid}/{version}/enable", dependencies=[Depends(require_admin)])
async def enable(request: Request, pid: str, version: str, body: EnableIn):
    try:
        return mgr(request).enable(pid, version, body.accept_hash, actor(request))
    except PluginError as exc:
        raise ApiError(409, "plugin_refused", str(exc)) from exc


@router.post("/plugins/{pid}/disable", dependencies=[Depends(require_admin)])
async def disable(request: Request, pid: str):
    mgr(request).disable(pid, actor(request))
    return {"plugin_id": pid, "enabled": False}


@router.post("/plugins/{pid}/{version}/activate", dependencies=[Depends(require_admin)])
async def activate(request: Request, pid: str, version: str):
    try:
        return mgr(request).activate(pid, version, actor(request))
    except PluginError as exc:
        raise ApiError(409, "plugin_refused", str(exc)) from exc


class UninstallIn(BaseModel):
    confirm: bool = False


@router.post("/plugins/{pid}/{version}/uninstall", dependencies=[Depends(require_admin)])
async def uninstall(request: Request, pid: str, version: str, body: UninstallIn):
    if not body.confirm:
        raise ApiError(422, "confirmation_required", "uninstalling removes the plugin files; send confirm=true (evidence is not touched)")
    try:
        return mgr(request).uninstall(pid, version, actor(request))
    except PluginError as exc:
        raise ApiError(404, "not_found", str(exc)) from exc


@router.post("/plugins/{pid}/{version}/contract-test")
async def contract_test(request: Request, pid: str, version: str):
    m = mgr(request)
    try:
        with S(request).sm() as db:
            row = m._row(db, pid, version)
            manifest = PluginManifest.model_validate(row.manifest_json)
        root = m._dir(pid, version)
        if tree_hash(root) != row.entry_sha256:
            raise PluginError("files changed since install")
    except PluginError as exc:
        raise ApiError(409, "plugin_refused", str(exc)) from exc
    return await run_contract_tests(root, manifest)
