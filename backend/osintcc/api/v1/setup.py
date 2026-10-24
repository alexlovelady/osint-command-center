"""First-run setup API: install optional tools and a local model, with progress. Admin only; every install needs `confirm`."""
from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy import select

from ...db.models import AiProfile, Setting
from ...main import ApiError
from ...setup import installer
from ...telemetry import audit
from .routes import S, actor, require_admin

router: APIRouter = APIRouter()
MAX_TASKS = 50


class InstallIn(BaseModel):
    ids: list[str] = Field(min_length=1, max_length=10)
    confirm: bool = False


class ModelIn(BaseModel):
    model_id: str | None = Field(default=None, max_length=200)
    enable_ai: bool = True
    confirm: bool = False


def _tasks(st: Any) -> dict[str, dict[str, Any]]:
    return st.setup_tasks


def _new_task(st: Any, kind: str, what: list[str]) -> dict[str, Any]:
    tasks = _tasks(st)
    while len(tasks) >= MAX_TASKS:
        tasks.pop(next(iter(tasks)))
    t: dict[str, Any] = {"id": str(uuid.uuid4()), "kind": kind, "what": what, "status": "running", "events": [], "results": [], "error": None,
         "started_at": datetime.now(UTC).isoformat(timespec="seconds")}
    tasks[t["id"]] = t
    return t


def _say(task: dict[str, Any]):
    def f(ev: dict[str, Any]) -> None:
        last = task["events"][-1] if task["events"] else None
        if last and last.get("phase") == ev.get("phase") == "download" and last.get("id") == ev.get("id"):
            task["events"][-1] = ev  # keep the log short: one live line per download
        else:
            task["events"].append(ev)
        task["events"] = task["events"][-200:]
    return f


def _gate(st: Any, confirm: bool) -> None:
    if st.settings.offline:
        raise ApiError(409, "offline", "offline mode is on; nothing was downloaded")
    if not confirm:
        raise ApiError(422, "confirmation_required", "review the plan and send confirm=true to start downloading")


@router.get("/setup/status")
async def setup_status(request: Request):
    st = S(request)
    out = await installer.status(st.settings)
    with st.sm() as db:
        row = db.get(Setting, "setup_completed")
        out["completed"] = bool(row and row.value_json)
        profiles = [p.model_id for p in db.scalars(select(AiProfile))]
    out["ai_profiles"] = profiles
    return out


@router.post("/setup/plan")
async def setup_plan(request: Request, body: InstallIn):
    try:
        return {"items": installer.plan(S(request).settings, body.ids)}
    except installer.SetupError as exc:
        raise ApiError(422, "not_installable", str(exc)) from exc


@router.post("/setup/install", status_code=202, dependencies=[Depends(require_admin)])
async def setup_install(request: Request, body: InstallIn):
    st = S(request)
    _gate(st, body.confirm)
    try:
        items = installer.plan(st.settings, body.ids)
    except installer.SetupError as exc:
        raise ApiError(422, "not_installable", str(exc)) from exc
    task = _new_task(st, "tools", [i["id"] for i in items])
    with st.sm() as db:
        audit.record(db, "setup.install_start", actor=actor(request), metadata={"ids": task["what"], "urls": [u for i in items for u in i["urls"]]})
        db.commit()

    async def work() -> None:
        say = _say(task)
        try:
            for tid in body.ids:
                try:
                    task["results"].append(await installer.install(st.settings, tid, progress=say))
                except installer.SetupError as exc:
                    task["results"].append({"id": tid, "error": str(exc)})
                    say({"phase": "error", "id": tid, "message": str(exc)})
            task["status"] = "done" if all("error" not in r for r in task["results"]) else "partial"
        except Exception as exc:
            task["status"], task["error"] = "failed", f"{type(exc).__name__}: {exc}"
        finally:
            with st.sm() as db:
                audit.record(db, "setup.install_end", actor="system", metadata={"status": task["status"], "ids": task["what"]})
                db.commit()
    t = asyncio.create_task(work())
    st.tasks.add(t)
    t.add_done_callback(st.tasks.discard)
    return {"task_id": task["id"], "plan": items}


@router.post("/setup/model", status_code=202, dependencies=[Depends(require_admin)])
async def setup_model(request: Request, body: ModelIn):
    st = S(request)
    _gate(st, body.confirm)
    status = await installer.status(st.settings)
    model = body.model_id or status["recommended_model"]["id"]
    if model not in {m["id"] for m in status["models"]}:
        raise ApiError(422, "unknown_model", "that model is not in the setup catalog")
    task = _new_task(st, "model", [model])
    with st.sm() as db:
        audit.record(db, "setup.model_start", actor=actor(request), metadata={"model": model, "source": "ollama.com registry via the local Ollama"})
        db.commit()

    async def work() -> None:
        say = _say(task)
        try:
            if not installer.ollama_path():
                say({"phase": "dependency", "id": "ollama"})
                task["results"].append(await installer.install(st.settings, "ollama", progress=say))
            task["results"].append(await installer.pull_model(model, say))
            with st.sm() as db:
                name = f"Local uncensored ({model.split('/')[-1]})"[:80].replace(":", " ")
                if not db.scalars(select(AiProfile).where(AiProfile.model_id == model)).first():
                    db.add(AiProfile(name=name, provider_type="ollama", model_id=model, local_only=True, config_json={"base_url": installer.OLLAMA}))
                if body.enable_ai:
                    db.merge(Setting(key="ai_enabled", value_json=True))
                audit.record(db, "setup.model_ready", actor="system", metadata={"model": model, "ai_enabled": body.enable_ai})
                db.commit()
            task["status"] = "done"
        except installer.SetupError as exc:
            task["status"], task["error"] = "failed", str(exc)
        except Exception as exc:
            task["status"], task["error"] = "failed", f"{type(exc).__name__}: {exc}"
    t = asyncio.create_task(work())
    st.tasks.add(t)
    t.add_done_callback(st.tasks.discard)
    return {"task_id": task["id"], "model": model}


@router.get("/setup/tasks/{task_id}")
async def setup_task(request: Request, task_id: str):
    t = _tasks(S(request)).get(task_id)
    if not t:
        raise ApiError(404, "not_found", "task not found")
    return t


@router.post("/setup/complete", dependencies=[Depends(require_admin)])
async def setup_complete(request: Request):
    st = S(request)
    with st.sm() as db:
        db.merge(Setting(key="setup_completed", value_json=True))
        audit.record(db, "setup.complete", actor=actor(request))
        db.commit()
    return {"completed": True}
