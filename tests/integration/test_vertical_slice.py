from __future__ import annotations

from osintcc.adapters.registry import default_adapters
from osintcc.db.models import (
    Case,
    Entity,
    Evidence,
    Finding,
    Job,
    JobEvent,
    Relationship,
    RelationshipEvidence,
)
from osintcc.evidence.vault import Vault
from osintcc.search import service
from osintcc.telemetry import audit
from sqlalchemy import func, select


def _case(sm):
    with sm() as db:
        c = Case(title="t", category="cyber")
        db.add(c)
        db.commit()
        return c.id


async def _launch(sm, settings, runner, case_id, raw="Example.COM", selected=None):
    adapters = default_adapters()
    with sm() as db:
        case = db.get(Case, case_id)
        parsed, plan = service.preview(db, case, raw, None, adapters, settings, selected)
        run = service.create_run(db, case, parsed, plan, confirmed=[])
        db.commit()
        run_id = run.id
    await runner.run_until_idle(run_id)
    return run_id


async def test_domain_slice_creates_cited_findings(sm, settings, make_runner, calls):
    runner = make_runner(calls)
    cid = _case(sm)
    run_id = await _launch(sm, settings, runner, cid)
    with sm() as db:
        run = db.get(__import__("osintcc.db.models", fromlist=["SearchRun"]).SearchRun, run_id)
        jobs = {j.adapter_id: j for j in db.scalars(select(Job).where(Job.run_id == run_id))}
        # at least three working sources, subfinder absent => skipped, not fatal
        ok = [a for a, j in jobs.items() if j.status == "succeeded"]
        assert {"rdap", "dns", "crtsh", "wayback"} <= set(ok)
        assert jobs["subfinder"].status in ("skipped", "succeeded")  # absent tool => skipped, never fatal
        assert run.status == "succeeded"
        findings = db.scalars(select(Finding).where(Finding.case_id == cid)).all()
        assert len(findings) > 10
        # every finding cites stored evidence with a matching vault hash
        vault = Vault(settings.vault_dir)
        for f in findings:
            ev = db.get(Evidence, f.evidence_id)
            assert ev and vault.verify(ev.vault_relpath, ev.sha256)
            assert f.confidence_reason and f.adapter_version
        # every relationship has evidence
        for rel in db.scalars(select(Relationship)):
            n = db.scalar(select(func.count()).select_from(RelationshipEvidence)
                          .where(RelationshipEvidence.relationship_id == rel.id))
            assert n >= 1
        names = {e.canonical_key for e in db.scalars(select(Entity).where(Entity.type == "domain"))}
        assert {"example.com", "www.example.com", "mail.example.com", "a.iana-servers.net"} <= names
        assert "unrelated.org" not in names  # out-of-domain CT names are dropped
        assert audit.verify_chain(db)[0]


async def test_rerun_is_idempotent_no_duplicate_findings(sm, settings, make_runner, calls):
    runner = make_runner(calls)
    cid = _case(sm)
    await _launch(sm, settings, runner, cid)
    with sm() as db:
        before = db.scalar(select(func.count()).select_from(Finding))
        ev_before = db.scalar(select(func.count()).select_from(Evidence))
    await _launch(sm, settings, runner, cid)
    with sm() as db:
        assert db.scalar(select(func.count()).select_from(Finding)) == before
        assert db.scalar(select(func.count()).select_from(Evidence)) == ev_before


async def test_failing_source_is_nonfatal_and_run_is_partial(sm, settings, make_runner, calls):
    runner = make_runner(calls, fail_crt=True)
    cid = _case(sm)
    # bound retries so the test is fast
    run_id = None
    adapters = default_adapters()
    with sm() as db:
        case = db.get(Case, cid)
        parsed, plan = service.preview(db, case, "example.com", None, adapters, settings)
        run = service.create_run(db, case, parsed, plan, confirmed=[])
        for j in db.scalars(select(Job).where(Job.run_id == run.id)):
            j.max_attempts = 1
        db.commit()
        run_id = run.id
    await runner.run_until_idle(run_id)
    with sm() as db:
        jobs = {j.adapter_id: j.status for j in db.scalars(select(Job).where(Job.run_id == run_id))}
        assert jobs["crtsh"] == "failed" and jobs["rdap"] == "succeeded" and jobs["dns"] == "succeeded"
        from osintcc.db.models import SearchRun
        assert db.get(SearchRun, run_id).status == "partial"


async def test_missing_cli_tool_is_skipped_not_fatal(sm, settings, make_runner, calls):
    runner = make_runner(calls)
    cid = _case(sm)
    run_id = await _launch(sm, settings, runner, cid, selected=["rdap", "subfinder"])
    with sm() as db:
        jobs = {j.adapter_id: j for j in db.scalars(select(Job).where(Job.run_id == run_id))}
        if jobs["subfinder"].status == "skipped":
            assert jobs["subfinder"].last_error_code == "not_installed"
        assert jobs["rdap"].status == "succeeded"


async def test_crash_recovery_requeues_running_jobs(sm, settings, make_runner, calls):
    runner = make_runner(calls)
    cid = _case(sm)
    adapters = default_adapters()
    with sm() as db:
        case = db.get(Case, cid)
        parsed, plan = service.preview(db, case, "example.com", None, adapters, settings)
        run = service.create_run(db, case, parsed, plan, confirmed=[])
        for j in db.scalars(select(Job).where(Job.run_id == run.id)):
            j.status = "running"  # simulate force-kill mid-run
            j.attempts = 1
        db.commit()
        run_id = run.id
    assert runner.recover_interrupted() == 5
    await runner.run_until_idle(run_id)
    with sm() as db:
        assert all(j.status in ("succeeded", "skipped") for j in db.scalars(select(Job).where(Job.run_id == run_id)))
        keys = db.scalars(select(Finding.dedup_key)).all()
        assert len(keys) == len(set(keys))  # no duplicate evidence/findings after recovery
        assert db.scalar(select(func.count()).select_from(JobEvent).where(JobEvent.event_type == "recovered")) == 5
