"""Install / review / enable / roll back plugins; keeps the live adapter registry in sync."""
from __future__ import annotations

import json
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import select

from ..db.models import PluginManifest as PluginRow
from ..telemetry import audit
from . import (
    HOST_API,
    PLATFORM,
    QUARANTINE_AFTER,
    PluginAdapter,
    PluginError,
    PluginManifest,
    adapter_id_for,
    copy_plugin,
    safe_rel,
    tree_hash,
    validate_manifest,
)


class PluginManager:
    def __init__(self, st):
        self.st = st

    @property
    def root(self) -> Path:
        return self.st.settings.data_dir / "plugins"

    def _dir(self, pid: str, version: str) -> Path:
        return self.root / pid / version

    # ------------------------------------------------------------------ install --------------------------------
    def install(self, src: Path, actor: str) -> dict[str, Any]:
        src = Path(src).resolve()
        mf = src / "plugin.json"
        if not src.is_dir() or not mf.is_file():
            raise PluginError("path must be a folder containing plugin.json")
        try:
            m = validate_manifest(json.loads(mf.read_text(encoding="utf8")))
        except ValueError as exc:
            if isinstance(exc, PluginError):
                raise
            raise PluginError("plugin.json is not valid JSON") from exc
        if not (src / safe_rel(m.entrypoint)).is_file() or not (src / safe_rel(m.fixture_path)).is_file():
            raise PluginError("entrypoint and fixture_path must exist inside the plugin")
        if adapter_id_for(m.id) in self.st.adapters and not self._is_plugin_adapter(adapter_id_for(m.id)):
            raise PluginError("this id collides with a built-in adapter")
        dest = self._dir(m.id, m.version)
        if dest.exists():
            raise PluginError(f"{m.id} {m.version} is already installed; bump the version to upgrade")
        dest.parent.mkdir(parents=True, exist_ok=True)
        try:
            copy_plugin(src, dest)
        except PluginError:
            shutil.rmtree(dest, ignore_errors=True)
            if dest.parent.exists() and not any(dest.parent.iterdir()):
                dest.parent.rmdir()  # leave nothing behind after a refused install
            raise
        h = tree_hash(dest)
        with self.st.sm() as db:
            row = PluginRow(plugin_id=m.id, version=m.version, enabled=False, is_active=False, license=m.license, entry_sha256=h,
                            capabilities_json=m.capabilities, permission_manifest_json=m.minimum_permissions.model_dump(),
                            manifest_json=m.model_dump(), health_status="installed_disabled")
            db.add(row)
            audit.record(db, "plugin.install", actor=actor, resource_id=row.id, metadata={"plugin": m.id, "version": m.version, "sha256": h})
            db.commit()
            return self.describe(db, row)

    def _is_plugin_adapter(self, aid: str) -> bool:
        return isinstance(self.st.adapters.get(aid), PluginAdapter)

    # ------------------------------------------------------------------ review / enable ------------------------
    def enable(self, plugin_id: str, version: str, accept_hash: str, actor: str) -> dict[str, Any]:
        with self.st.sm() as db:
            row = self._row(db, plugin_id, version)
            m = PluginManifest.model_validate(row.manifest_json)
            d = self._dir(plugin_id, version)
            if not d.is_dir() or tree_hash(d) != row.entry_sha256:
                raise PluginError("plugin files do not match the hash recorded at install; remove and reinstall it")
            if accept_hash != row.entry_sha256:
                raise PluginError("accept_hash must equal the tree hash you reviewed")
            if m.min_host_api > HOST_API:
                raise PluginError(f"plugin needs host API {m.min_host_api}; this app provides {HOST_API}")
            if PLATFORM not in m.platforms:
                raise PluginError(f"plugin does not support {PLATFORM}")
            for other in db.scalars(select(PluginRow).where(PluginRow.plugin_id == plugin_id)):
                other.is_active = False
            row.enabled, row.is_active, row.reviewed_by, row.reviewed_at = True, True, actor, datetime.now(UTC)
            row.health_status, row.invalid_outputs = "enabled", 0
            audit.record(db, "plugin.enable", actor=actor, resource_id=row.id, metadata={"plugin": plugin_id, "version": version, "sha256": row.entry_sha256})
            db.commit()
        self.sync()
        with self.st.sm() as db:
            return self.describe(db, self._row(db, plugin_id, version))

    def disable(self, plugin_id: str, actor: str) -> None:
        with self.st.sm() as db:
            for row in db.scalars(select(PluginRow).where(PluginRow.plugin_id == plugin_id)):
                row.enabled = row.is_active = False
                row.health_status = "disabled"
            audit.record(db, "plugin.disable", actor=actor, metadata={"plugin": plugin_id})
            db.commit()
        self.sync()

    def activate(self, plugin_id: str, version: str, actor: str) -> dict[str, Any]:
        """Rollback/upgrade switch between versions that were each reviewed and enabled before. Evidence is untouched: every
        finding keeps the adapter version that produced it."""
        with self.st.sm() as db:
            row = self._row(db, plugin_id, version)
            if row.reviewed_at is None:
                raise PluginError("that version has never been reviewed; enable it with its hash instead")
            d = self._dir(plugin_id, version)
            if tree_hash(d) != row.entry_sha256:
                raise PluginError("files changed since review")
            for other in db.scalars(select(PluginRow).where(PluginRow.plugin_id == plugin_id)):
                other.is_active = other.id == row.id
            row.enabled = True
            audit.record(db, "plugin.activate", actor=actor, metadata={"plugin": plugin_id, "version": version})
            db.commit()
        self.sync()
        with self.st.sm() as db:
            return self.describe(db, self._row(db, plugin_id, version))

    def uninstall(self, plugin_id: str, version: str, actor: str) -> dict[str, Any]:
        with self.st.sm() as db:
            row = self._row(db, plugin_id, version)
            m = PluginManifest.model_validate(row.manifest_json)
            d = self._dir(plugin_id, version)
            removed = []
            for rel in m.uninstall_cleanup:
                p = (d / safe_rel(rel)).resolve()
                if d.resolve() in p.parents and p.exists():
                    shutil.rmtree(p, ignore_errors=True) if p.is_dir() else p.unlink()
                    removed.append(rel)
            shutil.rmtree(d, ignore_errors=True)
            db.delete(row)
            audit.record(db, "plugin.uninstall", actor=actor, metadata={"plugin": plugin_id, "version": version})
            db.commit()
        self.sync()
        return {"uninstalled": f"{plugin_id}@{version}", "cleaned": removed, "evidence": "untouched"}

    # ------------------------------------------------------------------ registry sync --------------------------
    def sync(self) -> None:
        """Make the live adapter registry match the DB (same dict object the job runner holds)."""
        for aid in [a for a in self.st.adapters if self._is_plugin_adapter(a)]:
            del self.st.adapters[aid]
        with self.st.sm() as db:
            for row in db.scalars(select(PluginRow).where(PluginRow.is_active.is_(True), PluginRow.enabled.is_(True))):
                d = self._dir(row.plugin_id, row.version)
                if not d.is_dir():
                    row.health_status = "missing_files"
                    continue
                if tree_hash(d) != row.entry_sha256:  # files changed on disk since review: never re-register
                    row.enabled = row.is_active = False
                    row.health_status = "tampered"
                    audit.record(db, "plugin.tampered", actor="plugin-host", metadata={"plugin": row.plugin_id, "version": row.version})
                    continue
                m = PluginManifest.model_validate(row.manifest_json)
                self.st.adapters[adapter_id_for(row.plugin_id)] = PluginAdapter(m, d, row.entry_sha256, self.record_invalid)
            db.commit()

    def record_invalid(self, plugin_id: str, version: str, why: str) -> None:
        """Called by the adapter on malformed output or a policy violation. Quarantine after repeated offences."""
        with self.st.sm() as db:
            row = db.scalars(select(PluginRow).where(PluginRow.plugin_id == plugin_id, PluginRow.version == version)).first()
            if not row:
                return
            row.invalid_outputs += 1
            if row.invalid_outputs >= QUARANTINE_AFTER:
                row.enabled = row.is_active = False
                row.health_status = "quarantined"
            else:
                row.health_status = "degraded"
            audit.record(db, "plugin.invalid_output", actor="plugin-host", metadata={"plugin": plugin_id, "version": version, "why": why[:100],
                                                                                      "count": row.invalid_outputs})
            db.commit()
            quarantined = row.health_status == "quarantined"
        if quarantined:
            self.sync()

    # ------------------------------------------------------------------ queries ------------------------------
    def _row(self, db, plugin_id: str, version: str) -> PluginRow:
        row = db.scalars(select(PluginRow).where(PluginRow.plugin_id == plugin_id, PluginRow.version == version)).first()
        if not row:
            raise PluginError("plugin version not found")
        return row

    def describe(self, db, row: PluginRow) -> dict[str, Any]:
        m = PluginManifest.model_validate(row.manifest_json)
        d = self._dir(row.plugin_id, row.version)
        hash_ok = d.is_dir() and tree_hash(d) == row.entry_sha256
        compat = {"host_api_ok": m.min_host_api <= HOST_API, "platform_ok": PLATFORM in m.platforms, "output_schema_ok": m.output_schema_version == 1,
                  "hash_ok": hash_ok}
        return {"plugin_id": row.plugin_id, "version": row.version, "name": m.name, "maintainer": m.maintainer, "license": row.license,
                "enabled": row.enabled, "active": row.is_active, "health": row.health_status, "tree_sha256": row.entry_sha256,
                "capabilities": row.capabilities_json, "input_types": m.input_types, "permissions": row.permission_manifest_json,
                "active_network_access": m.active_network_access, "required_secrets": m.required_secrets, "rate_limits": m.rate_limits.model_dump(),
                "reviewed_by": row.reviewed_by, "reviewed_at": row.reviewed_at, "invalid_outputs": row.invalid_outputs, "compatibility": compat,
                "adapter_id": adapter_id_for(row.plugin_id),
                "network_isolation": "host-mediated requests with a declared-domain allow-list; the plugin process has no network client "
                                     "of its own, but OS-level network blocking is NOT enforced",
                "resource_limits": "time and output caps always; CPU/memory rlimits on POSIX only" }

    def list(self) -> list[dict[str, Any]]:
        with self.st.sm() as db:
            return [self.describe(db, r) for r in db.scalars(select(PluginRow).order_by(PluginRow.plugin_id, PluginRow.installed_at))]
