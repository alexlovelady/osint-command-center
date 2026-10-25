"""FastAPI application factory. Loopback only, per-launch bearer token, strict origins (spec 3, 7)."""
from __future__ import annotations

import asyncio
import logging
import os
import uuid
from collections.abc import Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from . import __version__
from .adapters.base import AdapterContext, IntelAdapter
from .adapters.registry import default_adapters
from .config import Settings
from .db import encrypt as db_encrypt
from .db import make_engine, session_factory
from .db.models import Setting, User, UserRole
from .evidence.crypto import VaultCipher, load_or_create_key
from .evidence.vault import Vault
from .jobs.runner import JobRunner
from .policy.ssrf import SafeHttp
from .telemetry import audit

if TYPE_CHECKING:
    from .plugins.manager import PluginManager
    from .workflows import Scheduler

LOCAL_USER_ID = "local-user"
PUBLIC_PATHS = {"/api/v1/health/live"}


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str, retryable: bool = False, details: dict | None = None):
        self.status, self.code, self.message, self.retryable, self.details = status, code, message, retryable, details or {}


@dataclass
class AppState:
    settings: Settings
    sm: sessionmaker
    vault: Vault
    adapters: dict[str, IntelAdapter]
    runner: JobRunner
    tokens: dict[str, str] = field(default_factory=dict)  # bearer token -> user id
    tasks: set = field(default_factory=set)
    scheduler: Scheduler | None = None
    ai_factory: Callable[[Any], Any] | None = None  # test/dev seam: profile -> Provider
    plugin_manager: PluginManager | None = None
    request_shutdown: Callable[[], None] | None = None  # set by run(): makes uvicorn exit gracefully
    db_key: bytes | None = None  # SQLCipher key when the database is encrypted
    setup_tasks: dict = field(default_factory=dict)  # first-run setup progress (in memory)
    secrets: Any = None  # SecretStore
    egress: Any = None  # startup egress self-check monitor (see selfcheck/egress.py)
    automation: Any = None  # AutomationEngine (runs, retries, recovery)
    automation_scheduler: Any = None  # AutomationScheduler (triggers, queue)
    aiv: Any = None  # AivExecutor (approved verification plans; never resumes an interrupted run)
    update_http: Any = None  # test/dev seam: SafeHttp used by the update check
    update_transport: Any = None  # test/dev seam: httpx transport used by the update download


def create_app(settings: Settings | None = None, *, adapters: dict[str, IntelAdapter] | None = None,
               ctx_factory=None, init_db: bool = True, vault_key: bytes | None = None) -> FastAPI:
    settings = settings or Settings()
    settings.ensure_dirs()
    for noisy in ("httpx", "httpcore"):         # their INFO lines print every requested URL: target identifiers and hash prefixes must not reach any log
        logging.getLogger(noisy).setLevel(logging.WARNING)
    master = vault_key
    if master is None and (settings.vault_encryption != "off" or settings.db_encryption_mode != "off"):
        master = load_or_create_key()
    db_key = db_encrypt.prepare(settings.db_path, master, settings.db_encryption_mode)
    engine = make_engine(settings.db_path, db_key)
    if init_db:
        _init_schema(engine, settings.db_path)
    sm = session_factory(engine)
    with sm() as db:
        if not db.get(User, LOCAL_USER_ID):
            db.add(User(id=LOCAL_USER_ID, display_name="Local investigator"))
            db.commit()
        if db.get(UserRole, (LOCAL_USER_ID, "role-admin")) is None:  # single-user v1: the local investigator administers the app
            db.add(UserRole(user_id=LOCAL_USER_ID, role_id="role-admin"))
            db.commit()
    cipher = None
    if settings.vault_encryption != "off":
        cipher = VaultCipher(master) if master else None
    vault = Vault(settings.vault_dir, cipher, require_encryption=settings.vault_encryption != "off")
    adapters = adapters or default_adapters(settings)
    http = SafeHttp(allow_private=settings.allow_private_destinations)

    def _default_ctx() -> AdapterContext:
        with sm() as db:
            row = db.get(Setting, "edgar_contact")
            cfg = {"edgar_user_agent": row.value_json if row else None, "allow_private": settings.allow_private_destinations}
        return AdapterContext(http=http, config=cfg, secret=state.secrets.get)

    ctx_factory = ctx_factory or _default_ctx
    runner = JobRunner(sm, settings, vault, adapters, ctx_factory)
    state = AppState(settings, sm, vault, adapters, runner, tokens={settings.session_token: LOCAL_USER_ID}, db_key=db_key)
    from .secrets_store import SecretStore
    state.secrets = SecretStore(sm, vault)
    from .workflows import Scheduler
    scheduler = Scheduler(state)
    state.scheduler = scheduler
    from .automations.executor import AutomationEngine
    from .automations.scheduler import AutomationScheduler
    state.automation = AutomationEngine(state, backoff_scale=settings.retry_scale)
    state.automation_scheduler = AutomationScheduler(state, state.automation)
    from .aiv.executor import AivExecutor
    state.aiv = AivExecutor(state)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        recovered = runner.recover_interrupted()
        app.state.recovered_jobs = recovered
        scheduler.recover()
        app.state.recovered_automation_runs = state.automation.recover()
        app.state.recovered_aiv_runs = state.aiv.recover()
        from .plugins.manager import PluginManager
        state.plugin_manager = PluginManager(state)
        state.plugin_manager.sync()  # re-register enabled, hash-verified plugins
        from .api.v1.hardware import recover_sessions
        app.state.recovered_captures = recover_sessions(sm)
        if settings.run_scheduler:
            scheduler.start()
            state.automation_scheduler.start()
        egress_task = None
        if settings.run_scheduler and os.environ.get("OSINTCC_EGRESS_SELFCHECK", "1") != "0":
            from .selfcheck.egress import EgressMonitor

            def _done(st: dict) -> None:
                with sm() as db:
                    audit.record(db, "selfcheck.egress", actor="system", metadata={k: st[k] for k in ("verdict", "samples", "window_s", "user_activity")}
                                 | {"offenders": st["offenders"][:10], "engine_connections": len(st["engine_connections"])})
                    db.commit()
            busy = lambda: bool(state.tasks) or any(t["status"] == "running" for t in state.setup_tasks.values())
            state.egress = EgressMonitor(window_s=float(os.environ.get("OSINTCC_EGRESS_WINDOW_S", "90")), busy=busy, on_done=_done)
            egress_task = asyncio.create_task(state.egress.run())
        yield
        if egress_task:
            egress_task.cancel()
        await scheduler.stop()
        await state.automation_scheduler.stop()
        for t in list(state.tasks) + list(state.aiv.tasks.values()):
            t.cancel()
        with engine.connect() as c:  # checkpoint WAL on clean shutdown
            c.exec_driver_sql("PRAGMA wal_checkpoint(TRUNCATE)")
        engine.dispose()

    app = FastAPI(title="OSINT Command Center", version=__version__, lifespan=lifespan, docs_url="/api/docs",
                  openapi_url="/api/openapi.json")
    app.state.core = state
    app.add_middleware(CORSMiddleware, allow_origins=list(settings.allowed_origins), allow_credentials=False,
                       allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
                       allow_headers=["Authorization", "Content-Type", "Last-Event-ID"])

    @app.middleware("http")
    async def guard(request: Request, call_next):
        rid = uuid.uuid4().hex[:12]
        request.state.request_id = rid
        origin = request.headers.get("origin")
        if origin and origin not in settings.allowed_origins:
            return _err(rid, 403, "origin_denied", "origin not allowed")
        path = request.url.path
        if path.startswith("/api/") and path not in PUBLIC_PATHS and request.method != "OPTIONS" \
                and path not in ("/api/docs", "/api/openapi.json"):
            auth = request.headers.get("authorization", "")
            token = auth[7:] if auth.lower().startswith("bearer ") else request.query_params.get("token", "")
            user = next((u for t, u in state.tokens.items() if _eq(t, token)), None) if token else None
            if not user:
                return _err(rid, 401, "unauthorized", "missing or invalid session token")
            request.state.user_id = user
        resp = await call_next(request)
        resp.headers["X-Request-ID"] = rid
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        return resp

    @app.exception_handler(ApiError)
    async def _api_err(request: Request, exc: ApiError):
        return _err(request.state.request_id, exc.status, exc.code, exc.message, exc.retryable, exc.details)

    @app.exception_handler(HTTPException)
    async def _http_err(request: Request, exc: HTTPException):
        return _err(getattr(request.state, "request_id", "-"), exc.status_code, "http_error", str(exc.detail))

    @app.exception_handler(RequestValidationError)
    async def _val_err(request: Request, exc: RequestValidationError):
        det = [{"loc": [str(x) for x in e["loc"]], "msg": e["msg"]} for e in exc.errors()]
        return _err(getattr(request.state, "request_id", "-"), 422, "validation_error", "invalid request", False,
                    {"errors": det})

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception):
        return _err(getattr(request.state, "request_id", "-"), 500, "internal_error", "unexpected server error",
                    False)

    from .api.v1.routes import router
    app.include_router(router, prefix="/api/v1")
    return app


def _eq(a: str, b: str) -> bool:
    import hmac
    return hmac.compare_digest(a.encode(), b.encode())


def _err(rid: str, status: int, code: str, message: str, retryable: bool = False, details: dict | None = None):
    return JSONResponse(status_code=status, content={"code": code, "message": message, "request_id": rid,
                                                     "retryable": retryable, "details_safe": details or {}})


def _init_schema(engine, db_path=None) -> None:
    """Apply Alembic migrations (adopting legacy DBs at baseline). Existing data is never dropped or recreated."""
    from .db.migrate import upgrade_to_head
    upgrade_to_head(engine, db_path)


def run() -> None:  # pragma: no cover - entry point for headless mode
    import secrets
    import sys

    import uvicorn

    settings = Settings()
    app = create_app(settings)
    port = int(os.environ.get("OSINTCC_PORT", "8791")) if "--dev-port" in sys.argv else 0
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)
    app.state.core.request_shutdown = lambda: setattr(server, "should_exit", True)

    async def serve() -> None:
        task = asyncio.create_task(server.serve())
        while not server.started:
            await asyncio.sleep(0.05)
        actual = server.servers[0].sockets[0].getsockname()[1]
        # Readiness message for the desktop shell (controlled IPC via stdout).
        print(f"OSINTCC_READY port={actual} token={settings.session_token}", flush=True)
        await task

    _ = secrets
    asyncio.run(serve())


__all__ = ["ApiError", "AppState", "create_app", "run", "select"]
