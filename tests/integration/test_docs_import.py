from __future__ import annotations

import io
import json
import zipfile
import zlib

import httpx
import pytest
from conftest import fake_dns, fake_resolver, make_handler
from osintcc.adapters.base import AdapterContext
from osintcc.ingest import docs
from osintcc.ingest.parsers import IngestError, detect_kind
from osintcc.main import create_app
from osintcc.policy.ssrf import SafeHttp


@pytest.fixture
async def api(settings, calls):
    http = SafeHttp(resolver=fake_resolver, transport=httpx.MockTransport(make_handler(calls)))
    app = create_app(settings, ctx_factory=lambda: AdapterContext(http=http, dns_query=fake_dns))
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1") as c:
            c.headers["Authorization"] = f"Bearer {settings.session_token}"
            c.app = app
            yield c


def make_pdf(js=False, open_action=False, link="https://docs.example.org/a?b=1", compressed_link="https://hidden.example.net/x") -> bytes:
    stream = zlib.compress(f"BT ({compressed_link} mail me at ops@example.net) Tj ET".encode())
    parts = [b"%PDF-1.7\n", b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n", b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n",
             b"3 0 obj<</Type/Page/Parent 2 0 R/Annots[<</Subtype/Link/A<</S/URI/URI(" + link.encode() + b")>>>>]>>endobj\n",
             b"4 0 obj<</Title(Quarterly)/Author(J. Doe)/Producer(Synthetic)>>endobj\n",
             b"5 0 obj<</Filter/FlateDecode/Length " + str(len(stream)).encode() + b">>stream\n" + stream + b"\nendstream endobj\n"]
    if js:
        parts.append(b"6 0 obj<</S/JavaScript/JS(app.alert(1))>>endobj\n")
    if open_action:
        parts.append(b"7 0 obj<</OpenAction 6 0 R>>endobj\n")
    parts.append(b"trailer<</Root 1 0 R>>\n%%EOF")
    return b"".join(parts)


def make_docx(macro=False, external="https://tracker.example.com/pixel", count=1) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("word/document.xml", "<w:document><w:body><w:p><w:r><w:t>Contact bob@example.org or see https://example.com/report</w:t></w:r></w:p></w:body></w:document>")
        z.writestr("word/_rels/document.xml.rels", f'<Relationships><Relationship Id="r1" Type="x" Target="{external}" TargetMode="External"/></Relationships>')
        z.writestr("docProps/core.xml", "<cp:coreProperties><dc:creator>Alice</dc:creator><cp:lastModifiedBy>Bob</cp:lastModifiedBy></cp:coreProperties>")
        z.writestr("docProps/app.xml", "<Properties><Application>Microsoft Office Word</Application></Properties>")
        if macro:
            z.writestr("word/vbaProject.bin", b"\x00\x01fake")
        for i in range(count - 1):
            z.writestr(f"extra/{i}.txt", b"x")
    return buf.getvalue()


def sf_export() -> bytes:
    rows = [{"type": "INTERNET_NAME", "data": "www.example.com", "module": "sfp_dnsresolve", "generated": 1700000000},
            {"type": "IP_ADDRESS", "data": "93.184.216.34", "module": "sfp_dnsresolve"},
            {"type": "EMAILADDR", "data": "Admin@Example.com", "module": "sfp_email"},
            {"type": "EMAILADDR", "data": "not-an-email", "module": "sfp_email"},
            {"type": "IP_ADDRESS", "data": "10.0.0.1", "module": "sfp_bad", "false_positive": 1},
            {"type": "SOFTWARE_USED", "data": "nginx 1.2", "module": "sfp_webserver"}]
    return json.dumps(rows).encode()


def test_pdf_flags_active_content_and_finds_links_inside_compressed_streams():
    p = docs.parse_pdf(make_pdf(js=True, open_action=True))
    o = p.observations[0].data
    assert o["active_content_present"] and o["risk_flags"]["javascript"] and o["risk_flags"]["open_action"]
    assert "https://docs.example.org/a?b=1" in o["urls"] and "https://hidden.example.net/x" in o["urls"]
    assert "ops@example.net" in o["emails"] and o["metadata_claimed_by_file"]["author"] == "J. Doe"
    assert any("active-content" in w for w in p.warnings)
    assert ("domain", "hidden.example.net") in {(e.type, e.key) for e in p.entities}
    assert "claims made by the file" in o["note"]


def test_clean_pdf_has_no_active_flag_and_rejects_non_pdf():
    p = docs.parse_pdf(make_pdf())
    assert not p.observations[0].data["active_content_present"] and not p.warnings
    with pytest.raises(IngestError):
        docs.parse_pdf(b"hello")


def test_corrupt_flate_stream_does_not_crash():
    junk = b"%PDF-1.4\n1 0 obj<<>>stream\nnot-zlib-data\nendstream endobj\n%%EOF"
    assert docs.parse_pdf(junk).kind == "pdf"


def test_docx_extracts_claims_macros_and_external_targets_without_fetching():
    p = docs.parse_docx(make_docx(macro=True))
    o = p.observations[0].data
    assert o["risk_flags"]["macros"] and o["macro_parts"] == ["word/vbaProject.bin"]
    assert o["external_targets"] == ["https://tracker.example.com/pixel"]
    assert "bob@example.org" in o["emails"] and "https://example.com/report" in o["urls"]
    assert o["metadata_claimed_by_file"]["creator"] == "Alice" and o["application_claimed_by_file"]["application"] == "Microsoft Office Word"
    assert any("NOT executed" in w for w in p.warnings) and any("none were fetched" in w for w in p.warnings)


def test_docx_rejects_non_docx_zip_bombs_and_unsafe_paths():
    with pytest.raises(IngestError):
        docs.parse_docx(b"plain text")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("other.txt", "x")
    with pytest.raises(IngestError, match="word/document.xml"):
        docs.parse_docx(buf.getvalue())
    with pytest.raises(IngestError, match="limits"):
        docs.parse_docx(make_docx(count=docs.MAX_ZIP_ENTRIES + 10))
    evil = io.BytesIO()
    with zipfile.ZipFile(evil, "w") as z:
        z.writestr("word/document.xml", "<w:t>x</w:t>")
        z.writestr("../escape.txt", "x")
    with pytest.raises(IngestError, match="unsafe"):
        docs.parse_docx(evil.getvalue())


def test_spiderfoot_import_is_leads_dedupes_and_drops_false_positives():
    p = docs.parse_spiderfoot(sf_export())
    keys = {(e.type, e.key) for e in p.entities}
    assert ("domain", "www.example.com") in keys and ("ip", "93.184.216.34") in keys and ("email", "admin@example.com") in keys
    assert ("ip", "10.0.0.1") not in keys and not any(k[1] == "not-an-email" for k in keys)
    assert p.summary["skipped"] == 1 and p.observations[0].data["event_type_counts"]["SOFTWARE_USED"] == 1
    assert any("leads, not findings" in w for w in p.warnings)
    with pytest.raises(IngestError):
        docs.parse_spiderfoot(b"{}")
    with pytest.raises(IngestError):
        docs.parse_spiderfoot(b"not json")


def test_detection_by_name_and_magic():
    assert detect_kind("report.pdf", b"") == "pdf" and detect_kind("x.bin", b"%PDF-1.4") == "pdf"
    assert detect_kind("memo.docx", b"PK") == "docx" and detect_kind("scan.spiderfoot.json", b"[") == "spiderfoot"


async def test_api_import_creates_evidence_entities_and_never_fetches_links(api, calls):
    cid = (await api.post("/api/v1/cases", json={"title": "D", "purpose": "document tests"})).json()["id"]
    before = len(calls)
    for name, data in (("report.pdf", make_pdf(js=True)), ("memo.docx", make_docx(macro=True)), ("scan.spiderfoot.json", sf_export())):
        r = await api.post(f"/api/v1/cases/{cid}/ingest?filename={name}&consent_confirmed=true", content=data)
        assert r.status_code == 201, r.text
    assert len(calls) == before  # embedded links are recorded, never requested
    ents = (await api.get(f"/api/v1/cases/{cid}/entities?limit=500")).json()["items"]
    assert {"domain", "email", "url", "ip"} <= {e["type"] for e in ents}
    obs = (await api.get(f"/api/v1/cases/{cid}/observations?discipline=OSINT")).json()["items"]
    assert {"document.pdf", "document.docx", "spiderfoot.export"} <= {o["kind"] for o in obs}
    assert all(o["access_class"] == "IMPORTED" for o in obs)
