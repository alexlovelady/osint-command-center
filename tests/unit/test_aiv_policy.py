"""AIV deterministic policy (addendum v1.1 sections 3 and 12: scope, windows, redirects, resolved addresses, budgets, plan shape)."""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from osintcc.aiv import plans, policy

NOW = datetime(2026, 10, 26, 12, 0, tzinfo=UTC)          # a Monday


def auth(**kw):
    base = dict(id="auth-1", asset_type="fqdn", canonical_scope=["example.org"], ports_json=[443], paths_json=["/"], allowed_classes_json=["http_metadata", "tls_handshake", "tcp_connect"],
                exclusions_json=[], limits_json={}, starts_at=NOW - timedelta(hours=1), expires_at=NOW + timedelta(days=7), revoked_at=None, retention_terms="")
    return SimpleNamespace(**{**base, **kw})


# ---- scope entries ----------------------------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("typ,val,ok", [("fqdn", "Example.ORG.", "example.org"), ("fqdn", "*.example.org", "*.example.org"), ("ip", "203.0.113.5", "203.0.113.5"),
                                         ("cidr", "203.0.113.0/24", "203.0.113.0/24"), ("url_prefix", "https://example.org:8443/app/", "https://example.org:8443/app")])
def test_canonical_entries(typ, val, ok):
    assert policy.canonical_entry(typ, val) == ok


@pytest.mark.parametrize("typ,val", [("fqdn", "localhost"), ("fqdn", "a b.example.org"), ("fqdn", "*.*.example.org"), ("fqdn", "*example.org"), ("ip", "example.org"), ("cidr", "10.0.0.0/8"),
                                      ("cidr", "203.0.113.5/24"), ("cidr", "203.0.113.0/23"), ("url_prefix", "ftp://example.org/"), ("url_prefix", "https://u:p@example.org/"),
                                      ("url_prefix", "https://example.org/?q=1"), ("fqdn", "")])
def test_bad_entries_are_refused(typ, val):
    with pytest.raises(ValueError):
        policy.canonical_entry(typ, val)


# ---- the gates --------------------------------------------------------------------------------------------------------------------------
def test_exact_host_port_path_and_class():
    a = auth()
    assert policy.check_url(a, "http_metadata", "https://example.org/", NOW)
    assert policy.check_url(a, "http_metadata", "https://example.org/deep/page", NOW)
    assert policy.check_url(a, "http_metadata", "https://sub.example.org/", NOW).code == "host_out_of_scope"      # a parent authorization does not cover children
    assert policy.check_url(a, "http_metadata", "https://example.org:8443/", NOW).code == "port_out_of_scope"
    assert policy.check_url(a, "http_metadata", "http://example.org/", NOW).code == "port_out_of_scope"           # port 80 was never authorized
    assert policy.check_url(a, "signature_check", "https://example.org/", NOW).code == "class_not_allowed"
    assert policy.check_url(a, "http_metadata", "ftp://example.org/", NOW).code == "scheme_denied"
    assert policy.check_url(a, "http_metadata", "https://user:pw@example.org/", NOW).code == "credentials_in_url"
    assert policy.check_url(a, "http_metadata", "https://127.0.0.1/", NOW).code == "host_out_of_scope"


def test_wildcard_covers_exactly_one_label():
    a = auth(canonical_scope=["*.example.org"])
    assert policy.check_url(a, "http_metadata", "https://www.example.org/", NOW)
    assert policy.check_url(a, "http_metadata", "https://a.b.example.org/", NOW).code == "host_out_of_scope"
    assert policy.check_url(a, "http_metadata", "https://example.org/", NOW).code == "host_out_of_scope"
    assert policy.check_url(a, "http_metadata", "https://evilexample.org/", NOW).code == "host_out_of_scope"


def test_paths_and_exclusions():
    a = auth(paths_json=["/public"], exclusions_json=["path:/public/admin", "port:9999", "www.example.org"], canonical_scope=["example.org", "www.example.org"])
    assert policy.check_url(a, "http_metadata", "https://example.org/public", NOW)
    assert policy.check_url(a, "http_metadata", "https://example.org/public/x", NOW)
    assert policy.check_url(a, "http_metadata", "https://example.org/private", NOW).code == "path_out_of_scope"
    assert policy.check_url(a, "http_metadata", "https://example.org/publicity", NOW).code == "path_out_of_scope"      # a prefix is a path boundary, not a string prefix
    assert policy.check_url(a, "http_metadata", "https://example.org/public/admin/x", NOW).code == "excluded"
    assert policy.check_url(a, "http_metadata", "https://www.example.org/public", NOW).code == "excluded"


def test_ip_and_cidr_assets():
    a = auth(asset_type="cidr", canonical_scope=["203.0.113.0/24"], ports_json=[80, 443])
    assert policy.check_host_port(a, "tcp_connect", "203.0.113.77", 80, NOW)
    assert policy.check_host_port(a, "tcp_connect", "203.0.114.1", 80, NOW).code == "host_out_of_scope"
    assert policy.check_host_port(a, "tcp_connect", "example.org", 80, NOW).code == "host_out_of_scope"           # a name is not an address of this block
    b = auth(asset_type="url_prefix", canonical_scope=["https://example.org/app"], ports_json=[443])
    assert policy.check_url(b, "http_metadata", "https://example.org/app/x", NOW)
    assert policy.check_url(b, "http_metadata", "https://example.org/other", NOW).code == "host_out_of_scope"
    assert policy.check_url(b, "http_metadata", "http://example.org/app", NOW).code in ("host_out_of_scope", "port_out_of_scope")


def test_lifetime_revocation_and_windows():
    assert policy.authorization_live(None, NOW).code == "auth_missing"
    assert policy.authorization_live(auth(expires_at=NOW - timedelta(seconds=1)), NOW).code == "auth_expired"
    assert policy.authorization_live(auth(expires_at=NOW), NOW).code == "auth_expired"                      # the end instant itself is already outside
    assert policy.authorization_live(auth(starts_at=NOW + timedelta(minutes=1)), NOW).code == "auth_not_started"
    assert policy.authorization_live(auth(revoked_at=NOW - timedelta(minutes=5)), NOW).code == "auth_revoked"
    win = {"windows": [{"days": [0, 1], "start": "09:00", "end": "17:00"}], "timezone": "America/New_York"}
    assert not policy.authorization_live(auth(limits_json=win), NOW)                                       # Monday 12:00 UTC is 08:00 in New York: before the 09:00 window
    assert policy.authorization_live(auth(limits_json=win), NOW + timedelta(hours=2))                      # 10:00 local


def test_limits_can_only_be_lowered():
    assert policy.effective_limits({"max_requests": 10, "requests_per_second": 1})["max_requests"] == 10
    assert policy.effective_limits({"max_requests": 10_000})["max_requests"] == policy.DEFAULT_LIMITS["max_requests"]
    assert policy.effective_limits({"max_requests": 0})["max_requests"] == 1
    with pytest.raises(ValueError):
        policy.validate_limits({"max_requests": 1000})
    with pytest.raises(ValueError):
        policy.validate_limits({"unknown_limit": 1})
    with pytest.raises(ValueError):
        policy.validate_limits({"windows": [{"days": [9], "start": "09:00", "end": "10:00"}]})


# ---- redirects and resolved addresses ---------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("loc,code", [("https://evil.test/", "redirect_out_of_scope"), ("http://127.0.0.1/", "redirect_out_of_scope"), ("http://169.254.169.254/latest/meta-data/", "redirect_out_of_scope"),
                                       ("https://example.org:444/", "redirect_out_of_scope"), ("//evil.test/x", "redirect_out_of_scope")])
def test_redirects_leaving_scope_are_refused(loc, code):
    assert policy.check_redirect(auth(), "http_metadata", "https://example.org/a", loc, NOW, 0, 3).code == code


def test_redirect_inside_scope_and_hop_limit():
    assert policy.check_redirect(auth(), "http_metadata", "https://example.org/a", "/b", NOW, 0, 3)
    assert policy.check_redirect(auth(), "http_metadata", "https://example.org/a", "/b", NOW, 3, 3).code == "redirect_limit"


@pytest.mark.parametrize("ips", [["10.0.0.5"], ["192.168.1.1"], ["127.0.0.1"], ["169.254.169.254"], ["::1"], ["fe80::1"], ["93.184.216.34", "10.0.0.5"], ["0.0.0.0"], ["224.0.0.1"], []])
def test_forbidden_resolutions_fail_closed(ips):
    assert not policy.check_resolved(auth(), "example.org", ips)


def test_public_resolution_is_fine_and_lab_is_explicit():
    assert policy.check_resolved(auth(), "example.org", ["93.184.216.34"])
    assert not policy.check_resolved(auth(), "example.org", ["127.0.0.1"])
    lab = auth(allowed_classes_json=["http_metadata", policy.LAB_CLASS])
    assert policy.check_resolved(lab, "example.org", ["127.0.0.1"])
    assert policy.check_resolved(lab, "example.org", ["10.1.2.3"])
    assert not policy.check_resolved(lab, "example.org", ["169.254.169.254"])                             # the cloud metadata address is never reachable, lab or not
    assert not policy.check_resolved(lab, "example.org", ["224.0.0.1"])


def test_ip_authorization_must_contain_every_resolved_address():
    a = auth(asset_type="cidr", canonical_scope=["8.8.8.0/24"])
    assert policy.check_resolved(a, "8.8.8.9", ["8.8.8.9"])
    assert not policy.check_resolved(a, "8.8.8.9", ["1.1.1.1"])


def test_ports_validation():
    assert policy.validate_ports([80, 443], 10)
    assert not policy.validate_ports([], 10)
    assert not policy.validate_ports(list(range(1, 12)), 10)
    assert not policy.validate_ports([80, 80], 10)
    assert not policy.validate_ports([0], 10)
    assert not policy.validate_ports([70000], 10)


# ---- budgets -----------------------------------------------------------------------------------------------------------------------------
def test_budget_counts_rate_bytes_and_time():
    t = [0.0]
    b = policy.Budget(policy.effective_limits({"max_requests": 3, "requests_per_second": 2, "max_bytes": 2000, "max_runtime_seconds": 10}), clock=lambda: t[0])
    assert b.charge("http_metadata", "h") == 0
    assert 0.49 < b.charge("http_metadata", "h") <= 0.5                                                   # two per second per host
    assert b.charge("http_metadata", "other") == 0                                                        # another host has its own rate
    with pytest.raises(policy.BudgetExceeded):
        b.charge("http_metadata", "h")
    b.add_bytes(1500)
    with pytest.raises(policy.BudgetExceeded):
        b.add_bytes(600)
    t[0] = 11.0
    with pytest.raises(policy.BudgetExceeded):
        b.check_time()
    assert b.counts()["requests"] == 3 and b.counts()["by_class"] == {"http_metadata": 3}


def test_scope_snapshot_changes_when_the_scope_changes():
    a = auth()
    h1 = policy.scope_snapshot(a)
    a.ports_json = [443, 8443]
    assert policy.scope_snapshot(a) != h1
    assert policy.scope_snapshot(auth()) == h1


# ---- plans are data -----------------------------------------------------------------------------------------------------------------------
GOOD = [{"kind": "http_metadata", "url": "https://example.org/"}, {"kind": "tls_handshake", "host": "example.org", "port": 443}, {"kind": "tcp_connect", "host": "example.org", "ports": [443]}]


def test_plan_accepts_only_known_steps_and_rejects_everything_else():
    assert [s["kind"] for s in plans.parse_steps(GOOD)] == ["http_metadata", "tls_handshake", "tcp_connect"]
    bad = [
        [{"kind": "http_metadata", "url": "https://example.org/", "headers": {"Authorization": "Bearer x"}}],
        [{"kind": "http_metadata", "url": "https://example.org/", "body": "x"}],
        [{"kind": "http_metadata", "url": "https://example.org/", "method": "POST"}],
        [{"kind": "shell", "command": "nmap -A example.org"}],
        [{"kind": "tcp_connect", "host": "example.org", "ports": list(range(1, 12))}],
        [{"kind": "signature_check", "url": "https://example.org/", "template_ids": ["../../etc/passwd"]}],
        [{"kind": "signature_check", "url": "https://example.org/", "template_ids": ["a-template"], "template_path": "/tmp/x.yaml"}],
        [{"kind": "service_detect", "host": "example.org", "ports": [443], "tool": "nmap", "scripts": "vuln"}],
        [{"kind": "tls_handshake", "host": "example.org; rm -rf /", "port": 443}],
        [{"kind": "http_metadata", "url": "https://example.org/", "credentials": {"user": "a", "password": "b"}}],
        [],
        [GOOD[0]] * 13,
        "not a list",
    ]
    for b in bad:
        with pytest.raises(plans.PlanError):
            plans.parse_steps(b)


def test_preview_is_offline_deterministic_and_bound_to_the_scope():
    a = auth(allowed_classes_json=["http_metadata", "tls_handshake", "tcp_connect"], ports_json=[443])
    p1 = plans.preview(a, GOOD, NOW)
    p2 = plans.preview(a, GOOD, NOW + timedelta(minutes=5))
    assert p1["ok"] and p1["plan_hash"] == p2["plan_hash"] and p1["hosts"] == ["example.org"] and p1["disclosure"]["external_services"] == []
    assert p1["estimated_requests"] == 2 + 5 + 1
    a2 = auth(ports_json=[443, 8443], allowed_classes_json=a.allowed_classes_json)
    assert plans.preview(a2, GOOD, NOW)["plan_hash"] != p1["plan_hash"]                              # a wider scope is a different plan
    steps = json.loads(json.dumps(GOOD))
    steps[0]["method"] = "GET"
    assert plans.preview(a, steps, NOW)["plan_hash"] != p1["plan_hash"]


def test_preview_flags_every_problem():
    a = auth(canonical_scope=["example.org", "www.example.org"], ports_json=[443])
    out = plans.preview(a, [{"kind": "http_metadata", "url": "https://www.example.org/"}, {"kind": "http_metadata", "url": "https://example.org/"}], NOW)
    assert not out["ok"] and any("different hosts" in p for p in out["problems"])                      # one host per run
    out = plans.preview(a, [{"kind": "http_metadata", "url": "https://other.org/"}], NOW)
    assert not out["ok"] and out["steps"][0]["code"] == "host_out_of_scope"
    out = plans.preview(a, [{"kind": "signature_check", "url": "https://example.org/", "template_ids": ["x-template"]}], NOW)
    assert out["steps"][0]["code"] == "class_not_allowed"
    b = auth(allowed_classes_json=["signature_check"], ports_json=[443])
    out = plans.preview(b, [{"kind": "signature_check", "url": "https://example.org/", "template_ids": ["x-template"]}], NOW)
    assert out["steps"][0]["code"] == "template_not_approved"
    out = plans.preview(b, [{"kind": "signature_check", "url": "https://example.org/", "template_ids": ["x-template"]}], NOW, approved_templates={"x-template"})
    assert out["ok"]
    assert not plans.preview(auth(expires_at=NOW - timedelta(days=1)), GOOD, NOW)["ok"]
    assert not plans.preview(a, GOOD[:1], NOW, offline=True)["ok"]
    tiny = auth(limits_json={"max_requests": 2}, allowed_classes_json=["tls_handshake"], ports_json=[443])
    assert any("limit is 2" in p for p in plans.preview(tiny, GOOD[1:2], NOW)["problems"])
