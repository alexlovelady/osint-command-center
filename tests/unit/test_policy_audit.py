from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from osintcc.adapters.base import AdapterManifest
from osintcc.adapters.registry import default_adapters
from osintcc.db.models import AuditEvent, Case, ScopeAuthorization
from osintcc.policy import engine
from osintcc.policy.targets import detect_target
from osintcc.search import service
from osintcc.telemetry import audit


def active_manifest():
    return AdapterManifest(id="nmap-like", name="x", version="1", supported_target_types=["domain"],
                           operation_class="active", needs_network=True)


def test_active_denied_without_authorization(sm):
    with sm() as db:
        c = Case(title="t")
        db.add(c)
        db.commit()
        d = engine.evaluate(db, case_id=c.id, manifest=active_manifest(), target_canonical="example.com",
                            target_domain="example.com", mode="active", offline=False)
        assert not d.allowed and "authorization" in d.reason


def test_active_requires_valid_unexpired_unrevoked_scope(sm):
    with sm() as db:
        c = Case(title="t")
        db.add(c)
        db.flush()
        auth = ScopeAuthorization(case_id=c.id, scope_type="domain", scope_value="example.com", authorized_by="owner",
                                  allowed_classes_json=["active"], expires_at=datetime.now(UTC) + timedelta(days=1))
        db.add(auth)
        db.commit()
        args = dict(case_id=c.id, manifest=active_manifest(), target_domain=None, mode="active", offline=False)
        assert engine.evaluate(db, target_canonical="sub.example.com", **args).allowed
        assert not engine.evaluate(db, target_canonical="example.org", **args).allowed  # out of scope
        auth.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        db.commit()
        assert not engine.evaluate(db, target_canonical="example.com", **args).allowed  # expired
        auth.expires_at, auth.revoked_at = None, datetime.now(UTC)
        db.commit()
        assert not engine.evaluate(db, target_canonical="example.com", **args).allowed  # revoked


def test_offline_blocks_network_adapters_with_zero_requests(sm, settings, calls):
    settings.offline = True
    with sm() as db:
        c = Case(title="t")
        db.add(c)
        db.commit()
        parsed = detect_target("example.com")
        plan = service.build_plan(db, c, parsed, default_adapters(), settings)
        assert not any(x["needs_network"] for x in plan["steps"])  # network sources are withheld entirely offline
        assert any(x["adapter_id"] == "lookalike" and x["runnable"] for x in plan["steps"])  # local-only work still allowed
        with pytest.raises(service.PlanError):
            service.create_run(db, c, parsed, plan, confirmed=[])
    assert calls == []


def test_public_site_query_needs_confirmation_and_is_not_default(sm, settings):
    with sm() as db:
        c = Case(title="t", category="people", purpose="authorized brand-impersonation review")
        db.add(c)
        db.commit()
        parsed = detect_target("someone", "username")
        plan = service.build_plan(db, c, parsed, default_adapters(), settings, selected=["sherlock"])
        step = plan["steps"][0]
        assert step["runnable"] and step["requires_confirmation"]
        with pytest.raises(service.PlanError):
            service.create_run(db, c, parsed, plan, confirmed=[])  # unconfirmed => refused
        run = service.create_run(db, c, parsed, plan, confirmed=["sherlock"])
        assert run.selected_adapters_json == ["sherlock"]
        # default plan for a username must not silently include public-site queries
        assert service.build_plan(db, c, parsed, default_adapters(), settings)["steps"] == []


def test_people_case_requires_purpose(sm, settings):
    with sm() as db:
        c = Case(title="t", category="people", purpose="")
        db.add(c)
        db.commit()
        with pytest.raises(service.PlanError):
            service.build_plan(db, c, detect_target("x", "username"), default_adapters(), settings)


def test_audit_chain_detects_tampering(sm):
    with sm() as db:
        for i in range(5):
            audit.record(db, f"a{i}", metadata={"api_key": "SECRET123", "note": "x" * 500})
        db.commit()
        ok, n, bad = audit.verify_chain(db)
        assert ok and n == 5
        first = db.query(AuditEvent).order_by(AuditEvent.seq).first()
        assert first.metadata_json["api_key"] == "[redacted]" and len(first.metadata_json["note"]) < 250
        mid = db.query(AuditEvent).filter_by(seq=3).one()
        mid.action = "forged"
        db.commit()
        ok, _, bad = audit.verify_chain(db)
        assert not ok and bad == 3


def test_pdf_is_byte_reproducible_for_identical_input(tmp_path):
    import hashlib

    from osintcc.reporting.build import to_pdf
    d = {"profile": "technical", "generated_at": "2026-01-01T00:00:00+00:00",
         "case": {"title": "T", "purpose": "", "status": "open", "id": "x", "category": "cyber", "scope": {}},
         "limitations": "L", "findings": [{"subject": "a", "predicate": "p", "value": "v", "confidence": "high",
                                           "evidence_id": "e" * 36}],
         "evidence_manifest": [{"evidence_id": "e" * 36, "title": "t", "sha256": "0" * 64}],
         "evidence_manifest_sha256": "0" * 64}
    to_pdf(d, tmp_path / "a.pdf")
    to_pdf(d, tmp_path / "b.pdf")
    h = [hashlib.sha256((tmp_path / n).read_bytes()).hexdigest() for n in ("a.pdf", "b.pdf")]
    assert h[0] == h[1]
