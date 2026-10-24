"""Durable job runner + normalizer: adapter result -> vault, evidence, sources, entities, findings, edges."""
from __future__ import annotations

import asyncio
import hashlib
import json
import random
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from ..adapters.base import AdapterResult, EntityRef, IntelAdapter
from ..adapters.base import Target as ATarget
from ..config import Settings
from ..db.models import (
    Entity,
    Evidence,
    Finding,
    Job,
    JobEvent,
    Relationship,
    RelationshipEvidence,
    SearchRun,
    Source,
)
from ..db.models import Target as DbTarget
from ..evidence.vault import Vault
from ..policy import engine as policy
from ..policy.targets import domain_of
from ..telemetry import audit

LEASE_SECONDS = 120


def _now() -> datetime:
    return datetime.now(UTC)


def _aware(dt: datetime | None) -> datetime | None:
    return dt.replace(tzinfo=UTC) if dt is not None and dt.tzinfo is None else dt


def emit(db: Session, job: Job, event_type: str, payload: dict | None = None) -> None:
    seq = (db.scalar(select(func.max(JobEvent.sequence)).where(JobEvent.job_id == job.id)) or 0) + 1
    db.add(JobEvent(job_id=job.id, run_id=job.run_id, sequence=seq, event_type=event_type,
                    payload_json=payload or {}))


def upsert_entity(db: Session, case_id: str, ref: EntityRef) -> Entity:
    e = db.scalars(select(Entity).where(Entity.case_id == case_id, Entity.type == ref.type,
                                        Entity.canonical_key == ref.key)).first()
    now = _now()
    if e:
        e.last_seen_at = now
        return e
    e = Entity(case_id=case_id, type=ref.type, canonical_key=ref.key, display_name=ref.display or ref.key,
               first_seen_at=now, last_seen_at=now)
    db.add(e)
    db.flush()
    return e


def finding_dedup_key(case_id: str, subject_key: str, predicate: str, value, adapter_id: str) -> str:
    blob = json.dumps([case_id, subject_key, predicate, value, adapter_id], sort_keys=True, default=str)
    return hashlib.sha256(blob.encode()).hexdigest()


def persist_result(db: Session, vault: Vault, manifest, run: SearchRun, result: AdapterResult) -> dict:
    """Single transaction (caller commits). Idempotent: re-running the same result adds no duplicate rows."""
    retrieved = _now()
    ev_ids: list[str] = []
    for art in result.artifacts:
        sha256, sha512, relpath, size = vault.store(art.content)
        existing = db.scalars(select(Evidence).where(
            Evidence.case_id == run.case_id, Evidence.sha256 == sha256, Evidence.original_url == art.source_url,
            Evidence.kind == f"{manifest.id}.raw")).first()
        if existing:
            ev_ids.append(existing.id)
            continue
        src = Source(adapter_id=manifest.id, source_type="cli" if manifest.id in ("subfinder", "sherlock") else "http",
                     source_url=art.source_url, retrieved_at=retrieved, terms_url=manifest.terms_url,
                     license_notes=manifest.license, rate_class=manifest.operation_class,
                     metadata_json={"http_status": art.http_status, "adapter_version": manifest.version,
                                    "note": art.note})
        db.add(src)
        db.flush()
        ev = Evidence(case_id=run.case_id, source_id=src.id, kind=f"{manifest.id}.raw", title=art.name,
                      sha256=sha256, sha512=sha512, byte_size=size, mime_type=art.mime_type, vault_relpath=relpath,
                      original_url=art.source_url, retrieved_at=retrieved, observed_at=retrieved,
                      published_at=art.published_at, capture_method=f"adapter:{manifest.id}@{manifest.version}",
                      chain_of_custody_json=[{"event": "captured", "at": retrieved.isoformat(),
                                              "by": f"adapter:{manifest.id}", "sha256": sha256}])
        db.add(ev)
        db.flush()
        ev_ids.append(ev.id)
    new_findings = new_rels = 0
    result_keys: list[str] = []

    def ev_for(i: int) -> str | None:
        return ev_ids[i] if 0 <= i < len(ev_ids) else (ev_ids[0] if ev_ids else None)

    for fd in result.findings:
        eid = ev_for(fd.artifact_index)
        if eid is None:
            continue  # findings without evidence are never stored
        subj = upsert_entity(db, run.case_id, fd.subject)
        key = finding_dedup_key(run.case_id, fd.subject.key, fd.predicate, fd.value, manifest.id)
        result_keys.append(key)
        if db.scalars(select(Finding.id).where(Finding.case_id == run.case_id, Finding.dedup_key == key)).first():
            continue
        ev_row = db.get(Evidence, eid)
        if ev_row is None:
            continue
        db.add(Finding(case_id=run.case_id, subject_entity_id=subj.id, predicate=fd.predicate,
                       value_type=type(fd.value).__name__, value_json=fd.value, confidence=fd.confidence,
                       confidence_reason=fd.confidence_reason, evidence_id=eid, source_id=ev_row.source_id,
                       adapter_id=manifest.id, adapter_version=manifest.version, observed_at=retrieved,
                       source_published_at=fd.source_published_at, run_id=run.id, dedup_key=key))
        new_findings += 1
    for rd in result.relationships:
        eid = ev_for(rd.artifact_index)
        if eid is None:
            continue
        a, b = upsert_entity(db, run.case_id, rd.from_entity), upsert_entity(db, run.case_id, rd.to_entity)
        rel = db.scalars(select(Relationship).where(
            Relationship.case_id == run.case_id, Relationship.from_entity_id == a.id,
            Relationship.to_entity_id == b.id, Relationship.relation_type == rd.relation_type)).first()
        if not rel:
            rel = Relationship(case_id=run.case_id, from_entity_id=a.id, to_entity_id=b.id,
                               relation_type=rd.relation_type, confidence=rd.confidence,
                               confidence_reason=rd.confidence_reason, status="unverified", asserted_by=manifest.id)
            db.add(rel)
            db.flush()
            new_rels += 1
        if not db.get(RelationshipEvidence, (rel.id, eid)):
            db.add(RelationshipEvidence(relationship_id=rel.id, evidence_id=eid))
        # Independent corroboration: edge seen by >=2 distinct adapters becomes "corroborated".
        adapters_seen = {r[0] for r in db.execute(
            select(Evidence.kind).join(RelationshipEvidence, RelationshipEvidence.evidence_id == Evidence.id)
            .where(RelationshipEvidence.relationship_id == rel.id))}
        if len(adapters_seen) >= 2 and rel.status == "unverified":
            rel.status = "corroborated"
    db.flush()
    return {"evidence": len(ev_ids), "findings": new_findings, "relationships": new_rels, "result_keys": result_keys}


class JobRunner:
    def __init__(self, sm: sessionmaker, settings: Settings, vault: Vault, adapters: dict[str, IntelAdapter],
                 ctx_factory):
        self.sm, self.settings, self.vault, self.adapters = sm, settings, vault, adapters
        self.ctx_factory = ctx_factory
        self._sem = asyncio.Semaphore(settings.max_concurrency)
        self._cancel: set[str] = set()

    # ---- recovery -------------------------------------------------------------------------------------------
    def recover_interrupted(self) -> int:
        """Jobs left `running` by a crash/kill: requeue if retries remain (idempotent persistence), else mark."""
        n = 0
        with self.sm() as db:
            for job in db.scalars(select(Job).where(Job.status == "running")):
                if job.attempts >= job.max_attempts:
                    job.status, job.last_error_code = "interrupted", "interrupted"
                else:
                    job.status, job.lease_until = "queued", None
                emit(db, job, "recovered", {"attempts": job.attempts})
                n += 1
            db.commit()
        return n

    def cancel_run(self, run_id: str) -> None:
        self._cancel.add(run_id)
        with self.sm() as db:
            for job in db.scalars(select(Job).where(Job.run_id == run_id, Job.status.in_(("queued", "deferred")))):
                job.status = "cancelled"
                emit(db, job, "cancelled")
            audit.record(db, "search.cancel", resource_type="search_run", resource_id=run_id)
            db.commit()
        self._finalize(run_id)

    def abort_run(self, run_id: str) -> None:
        """Cancel EVERYTHING of a run, including jobs that are mid-flight (the caller has cancelled the asyncio tasks that were executing them)."""
        self._cancel.add(run_id)
        with self.sm() as db:
            for job in db.scalars(select(Job).where(Job.run_id == run_id, Job.status.in_(("queued", "deferred", "running")))):
                job.status = "cancelled"
                emit(db, job, "cancelled")
            audit.record(db, "search.cancel", resource_type="search_run", resource_id=run_id)
            db.commit()
        self._finalize(run_id)

    # ---- execution ------------------------------------------------------------------------------------------
    def _claim(self, db: Session, run_id: str | None) -> list[str]:
        now = _now()
        q = select(Job).where(Job.status.in_(("queued", "deferred")))
        if run_id:
            q = q.where(Job.run_id == run_id)
        ids = []
        for job in db.scalars(q):
            nra = _aware(job.next_retry_at)
            if nra is not None and nra > now:
                continue
            job.status, job.lease_until, job.started_at = "running", now + timedelta(seconds=LEASE_SECONDS), now
            job.attempts += 1
            emit(db, job, "started", {"attempt": job.attempts})
            ids.append(job.id)
        db.commit()
        return ids

    async def run_pending(self, run_id: str | None = None) -> None:
        with self.sm() as db:
            ids = self._claim(db, run_id)
        await asyncio.gather(*(self._run_job(i) for i in ids))
        runs = {r for (r,) in self._runs_for(ids)}
        for r in runs:
            self._finalize(r)

    def _runs_for(self, ids):
        with self.sm() as db:
            return [(j.run_id,) for j in db.scalars(select(Job).where(Job.id.in_(ids)))]

    async def run_until_idle(self, run_id: str, max_rounds: int = 6) -> None:
        for _ in range(max_rounds):
            await self.run_pending(run_id)
            with self.sm() as db:
                active = db.scalars(select(Job).where(Job.run_id == run_id,
                                                      Job.status.in_(("queued", "deferred", "running")))).all()
                if not active:
                    return
                waits = [(nra - _now()).total_seconds() for j in active if (nra := _aware(j.next_retry_at)) is not None]
            await asyncio.sleep(max(0.0, min(waits)) if waits else 0)

    async def _run_job(self, job_id: str) -> None:
        async with self._sem:
            with self.sm() as db:
                job = db.get(Job, job_id)
                run = db.get(SearchRun, job.run_id)
                target = db.get(DbTarget, run.target_id)
                adapter = self.adapters.get(job.adapter_id)
                at = ATarget(type=target.type, raw=target.raw_input, canonical=target.canonical_value)
                case_id, dom, mode = run.case_id, domain_of(target.type, target.canonical_value), run.mode
                # Execution-time policy re-check (spec 12.2): scope enforced again at adapter execution.
                if adapter is None:
                    return self._finish(db, job, "error", "unknown_adapter", ["adapter not registered"])
                if run.id in self._cancel:
                    return self._finish(db, job, "cancelled", None, [])
                d = policy.evaluate(db, case_id=case_id, manifest=adapter.manifest, target_canonical=at.canonical,
                                    target_domain=dom, mode=mode, offline=self.settings.offline)
                if not d.allowed:
                    audit.record(db, "adapter.denied", case_id=case_id, resource_type="job", resource_id=job.id,
                                 decision="deny", metadata={"adapter": job.adapter_id, "reason": d.reason})
                    return self._finish(db, job, "denied", "policy_denied", [d.reason])
            try:
                result = await asyncio.wait_for(adapter.run(at, self.ctx_factory()),
                                                adapter.manifest.timeout_seconds + 5)
            except TimeoutError:
                result = AdapterResult(adapter_id=job.adapter_id, status="error", error_code="timeout",
                                       retryable=True, warnings=["adapter exceeded its time budget"])
            except Exception as exc:  # adapter bugs must never crash the app
                result = AdapterResult(adapter_id=job.adapter_id, status="error", error_code="adapter_exception",
                                       warnings=[f"{type(exc).__name__}"])
            with self.sm() as db:
                job = db.get(Job, job_id)
                run = db.get(SearchRun, job.run_id)
                try:
                    counts = persist_result(db, self.vault, adapter.manifest, run, result)
                except Exception as exc:
                    db.rollback()
                    job = db.get(Job, job_id)
                    return self._finish(db, job, "error", "persist_error", [type(exc).__name__])
                if result.status in ("success", "partial", "skipped"):
                    job.result_keys_json = counts.pop("result_keys", [])
                    emit(db, job, "result", counts)
                    return self._finish(db, job, result.status, result.error_code, result.warnings)
                if result.retryable and job.attempts < job.max_attempts:
                    delay = (result.retry_after_seconds or min(300, 2 ** job.attempts) + random.random()) * self.settings.retry_scale
                    job.status = "deferred" if result.status == "rate_limited" else "queued"
                    job.next_retry_at = _now() + timedelta(seconds=delay)
                    job.last_error_code, job.warnings_json = result.error_code, result.warnings
                    emit(db, job, "retry_scheduled", {"in_seconds": round(delay, 1), "code": result.error_code})
                    db.commit()
                    return
                self._finish(db, job, "error" if result.status != "rate_limited" else "rate_limited",
                             result.error_code, result.warnings)

    def _finish(self, db: Session, job: Job, result_status: str, code: str | None, warnings: list[str]) -> None:
        job.status = {"success": "succeeded", "partial": "succeeded", "skipped": "skipped", "cancelled": "cancelled",
                      "denied": "denied"}.get(result_status, "failed")
        job.result_status, job.last_error_code, job.warnings_json = result_status, code, warnings
        job.finished_at, job.lease_until, job.next_retry_at = _now(), None, None
        emit(db, job, "finished", {"status": job.status, "code": code})
        db.commit()

    def _finalize(self, run_id: str) -> None:
        with self.sm() as db:
            run = db.get(SearchRun, run_id)
            jobs = db.scalars(select(Job).where(Job.run_id == run_id)).all()
            if not run or any(j.status in ("queued", "deferred", "running") for j in jobs):
                return
            st = [j.status for j in jobs]
            ok = st.count("succeeded")
            neutral = ok + st.count("skipped")
            run.status = ("cancelled" if st and all(s == "cancelled" for s in st) else
                          "skipped" if st and all(s == "skipped" for s in st) else
                          "succeeded" if ok and neutral == len(st) else "partial" if ok else "failed")
            run.ended_at = _now()
            run.summary_json = {"jobs": {s: st.count(s) for s in set(st)},
                                "findings": db.scalar(select(func.count()).select_from(Finding)
                                                      .where(Finding.run_id == run_id)) or 0,
                                "warnings": {j.adapter_id: j.warnings_json for j in jobs if j.warnings_json}}
            db.commit()
