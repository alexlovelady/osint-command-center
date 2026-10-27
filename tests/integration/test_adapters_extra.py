from __future__ import annotations

import base64
import json

import httpx
import pytest
from conftest import fake_dns, fake_resolver
from osintcc.adapters.base import AdapterContext, Target
from osintcc.adapters.cli import AmassAdapter, TheHarvesterAdapter
from osintcc.adapters.http import CensysAdapter, GdeltAdapter, OpenCorporatesAdapter
from osintcc.adapters.registry import default_adapters
from osintcc.policy.ssrf import SafeHttp
from osintcc.policy.targets import TargetError, canonicalize


def ctx_with(handler, secrets=None):
    calls: list[httpx.Request] = []

    def h(req):
        calls.append(req)
        return handler(req)
    http = SafeHttp(resolver=fake_resolver, transport=httpx.MockTransport(h))
    return AdapterContext(http=http, dns_query=fake_dns, secret=(secrets or {}).get), calls


def T(t, v):
    return Target(type=t, raw=v, canonical=canonicalize(t, v))


def test_company_target_is_strict_and_never_autodetected():
    assert canonicalize("company", "  Acme   Widgets  Ltd ") == "Acme Widgets Ltd"
    for bad in ("", "x", "-rf", "a\x00b", "z" * 121):
        with pytest.raises(TargetError):
            canonicalize("company", bad)


def test_new_adapters_registered_off_by_default_with_honest_labels():
    reg = default_adapters()
    for aid in ("gdelt", "opencorporates", "censys", "amass", "theharvester"):
        assert aid in reg and reg[aid].manifest.default_selected is False
    assert "no names" in reg["amass"].manifest.description and "API keys" in reg["amass"].manifest.description


GDELT = {"articles": [{"url": "https://news.example.com/a", "title": "Example expands", "seendate": "20250102T030405Z", "language": "English",
                       "sourcecountry": "US"}, {"title": "no url"}]}


async def test_gdelt_lists_articles_with_published_time_and_low_confidence():
    ctx, calls = ctx_with(lambda r: httpx.Response(200, json=GDELT))
    res = await GdeltAdapter().run(T("domain", "example.com"), ctx)
    assert res.status == "success" and "domain%3Aexample.com" in str(calls[0].url)
    art = next(f for f in res.findings if f.predicate == "gdelt.article")
    assert art.value["url"] == "https://news.example.com/a" and art.confidence == "low" and art.source_published_at.year == 2025
    assert sum(f.predicate == "gdelt.article" for f in res.findings) == 1  # the row without a URL is dropped


async def test_gdelt_empty_failure_and_garbage():
    ctx, _ = ctx_with(lambda r: httpx.Response(200, json={}))
    res = await GdeltAdapter().run(T("domain", "example.com"), ctx)
    assert res.status == "success" and "not evidence" in res.warnings[0]
    ctx, _ = ctx_with(lambda r: httpx.Response(429, headers={"retry-after": "30"}))
    assert (await GdeltAdapter().run(T("domain", "example.com"), ctx)).status == "rate_limited"
    ctx, _ = ctx_with(lambda r: httpx.Response(200, content=b"<html>"))
    res = await GdeltAdapter().run(T("domain", "example.com"), ctx)
    assert res.status == "error" and res.error_code == "parse_error" and res.artifacts


OC = {"results": {"companies": [{"company": {"name": "ACME LTD", "company_number": "123", "jurisdiction_code": "gb", "current_status": "Active",
                                              "opencorporates_url": "https://opencorporates.com/companies/gb/123"}},
                                {"company": {"name": "no number"}}]}}


async def test_opencorporates_needs_key_and_never_stores_it():
    ctx, calls = ctx_with(lambda r: httpx.Response(200, json=OC))
    res = await OpenCorporatesAdapter().run(T("company", "Acme"), ctx)
    assert res.status == "skipped" and res.error_code == "requires_key" and calls == []
    ctx, calls = ctx_with(lambda r: httpx.Response(200, json=OC), {"opencorporates": "TOKEN123"})
    res = await OpenCorporatesAdapter().run(T("company", "Acme"), ctx)
    assert res.status == "success" and "TOKEN123" in str(calls[0].url)
    assert "TOKEN123" not in (res.artifacts[0].source_url or "") and "TOKEN123" not in json.dumps([f.model_dump(mode="json") for f in res.findings])
    assert len(res.findings) == 1 and res.findings[0].subject.key == "gb:123" and res.findings[0].confidence == "medium"
    assert any("leads" in w for w in res.warnings)


LEGACY = "0b1c2d3e-aaaa-bbbb-cccc-1234567890ab:s3cr3tS3cr3tS3cr3tS3cr3tAA"


async def test_censys_basic_auth_header_and_failure_modes():
    body = {"result": {"services": [{"port": 443, "service_name": "HTTPS", "transport_protocol": "TCP"}],
                       "autonomous_system": {"asn": 15133, "name": "EDGECAST"}, "location": {"country_code": "US"}}}
    ctx, calls = ctx_with(lambda r: httpx.Response(200, json=body))
    assert (await CensysAdapter().run(T("ip", "93.184.216.34"), ctx)).status == "skipped" and calls == []
    ctx, calls = ctx_with(lambda r: httpx.Response(200, json=body), {"censys": "nocolon"})
    assert (await CensysAdapter().run(T("ip", "93.184.216.34"), ctx)).status == "skipped" and calls == []
    ctx, calls = ctx_with(lambda r: httpx.Response(200, json=body), {"censys": LEGACY})
    res = await CensysAdapter().run(T("ip", "93.184.216.34"), ctx)
    assert res.status == "success" and calls[0].headers["authorization"] == "Basic " + base64.b64encode(LEGACY.encode()).decode()
    assert "SECRET" not in json.dumps([f.model_dump(mode="json") for f in res.findings]) and {f.predicate for f in res.findings} >= {"censys.services"}
    for status, expect in ((404, "success"), (403, "skipped"), (500, "error")):
        ctx, _ = ctx_with(lambda r, s=status: httpx.Response(s), {"censys": LEGACY})
        assert (await CensysAdapter().run(T("ip", "93.184.216.34"), ctx)).status == expect


async def test_cli_adapters_report_not_installed_without_running_anything():
    for ad in (AmassAdapter(binary_path="/nonexistent"), TheHarvesterAdapter(binary_path="/nonexistent")):
        if ad.locate():
            pytest.skip("binary genuinely installed on this machine")
        h = await ad.health()
        assert h["status"] == "not_installed"
        res = await ad.run(T("domain", "example.com"), ctx_with(lambda r: httpx.Response(404))[0])
        assert res.status == "skipped" and res.error_code == "not_installed"


def test_cli_parsers_keep_only_hosts_under_the_target_and_are_argv_safe():
    t = T("domain", "example.com")
    am = AmassAdapter()
    f, rels = am.parse(t, b"www.example.com (FQDN) --> a_record --> 1.2.3.4\nevil.test --> x\nmail.example.com\nexample.com\n")
    assert {x.value for x in f} == {"www.example.com", "mail.example.com", "example.com"} and len(rels) == 2
    argv = am.build_argv("/bin/amass", t)
    assert argv[:7] == ["/bin/amass", "enum", "-passive", "-nocolor", "-silent", "-timeout", "3"] and argv[-2:] == ["-d", "example.com"] and argv[7] == "-dir"
    th = TheHarvesterAdapter()
    f, rels = th.parse(t, b"[*] Emails found:\nbob@example.com\nspam@other.org\n[*] Hosts found:\napi.example.com\n")
    assert {x.predicate for x in f} == {"theharvester.email", "theharvester.host"} and [x.value for x in f if x.predicate == "theharvester.email"] == ["bob@example.com"]
    assert len(rels) == 1


async def test_amass_runs_enum_then_subs_and_explains_an_empty_result(tmp_path, monkeypatch):
    from osintcc.adapters import cli as cli_mod
    calls = []

    async def fake(argv, timeout, max_output=0, **kw):
        calls.append(argv[1])
        return cli_mod.ProcResult(0, b"" if argv[1] == "enum" else b"www.example.com\napi.example.com\nother.test\n", b"")
    monkeypatch.setattr(cli_mod, "run_argv", fake)
    ad = AmassAdapter(binary_path=__file__, state_path=tmp_path / "tools" / "installed.json")
    res = await ad.run(T("domain", "example.com"), ctx_with(lambda r: httpx.Response(404))[0])
    assert calls == ["enum", "subs"] and res.status == "success" and {f.value for f in res.findings} == {"www.example.com", "api.example.com"}

    async def empty(argv, timeout, max_output=0, **kw):
        return cli_mod.ProcResult(0, b"No names were discovered\n", b"")
    monkeypatch.setattr(cli_mod, "run_argv", empty)
    res = await ad.run(T("domain", "example.com"), ctx_with(lambda r: httpx.Response(404))[0])
    assert res.status == "success" and not res.findings and "not evidence" in res.warnings[0]
