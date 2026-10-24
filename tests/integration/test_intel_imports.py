from __future__ import annotations

import json
import re
import struct
import sys
import zlib
from pathlib import Path

import httpx
import numpy as np
import pytest
from sqlalchemy import func, select

sys.path.insert(0, str(Path(__file__).parents[1] / "fixtures"))
import synthetic
import synthetic_intel as si
from conftest import fake_dns, fake_resolver, make_handler
from osintcc.adapters.base import AdapterContext
from osintcc.db.models import AuditEvent, Evidence, GraphProposal, Observation
from osintcc.ingest import fin, geo, net, parsers, tech, telemetry
from osintcc.main import create_app
from osintcc.policy.ssrf import SafeHttp

SRC = Path(__file__).parents[2] / "backend" / "osintcc"


@pytest.fixture
async def api(settings, calls):
    http = SafeHttp(resolver=fake_resolver, transport=httpx.MockTransport(make_handler(calls)))
    app = create_app(settings, ctx_factory=lambda: AdapterContext(http=http, dns_query=fake_dns))
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1") as c:
            c.headers["Authorization"] = f"Bearer {settings.session_token}"
            c.app = app
            yield c


async def case(c):
    return (await c.post("/api/v1/cases", json={"title": "Intel", "purpose": "synthetic fixtures"})).json()["id"]


async def imp(c, cid, name, data, **kw):
    q = f"filename={name}&consent_confirmed=true" + "".join(f"&{k}={v}" for k, v in kw.items())
    return await c.post(f"/api/v1/cases/{cid}/ingest?{q}", content=data)


# ================================================================== GEOINT ================================================
def test_exif_gps_parsed_with_signs_altitude_and_utc_time():
    p = geo.parse_jpeg_exif(si.jpeg_with_gps(48.8584, 2.2945, 35))
    d = p.observations[0].data
    assert d["has_gps"] and abs(d["location"]["lat"] - 48.8584) < 1e-4 and abs(d["location"]["lon"] - 2.2945) < 1e-4
    assert d["location"]["altitude_m"] == 35 and d["location"]["crs"] == "EPSG:4326"
    assert d["location"]["accuracy_m"] is None and "unknown" in d["location"]["accuracy_note"]  # never invented
    assert d["make"] == "FakeCo" and d["local_time_text"] == "2024:05:01 14:30:15"
    assert p.observations[0].observed_at.isoformat() == "2024-05-01T12:30:15+00:00"  # GPS UTC, not local text
    assert p.observations[0].sensitivity == "RESTRICTED"
    south_west = geo.parse_jpeg_exif(si.jpeg_with_gps(-33.8688, -70.6693)).observations[0].data["location"]
    assert south_west["lat"] < 0 and south_west["lon"] < 0
    assert geo.parse_jpeg_exif(si.jpeg_with_gps(hacc=5)).observations[0].data["location"]["accuracy_m"] == 5


def test_exif_without_gps_or_utc_time_is_honest():
    p = geo.parse_jpeg_exif(si.jpeg_with_gps(with_gps=False))
    assert not p.observations[0].data["has_gps"] and p.observations[0].kind == "media.exif"
    q = geo.parse_jpeg_exif(si.jpeg_with_gps(gps_time=False))
    assert q.observations[0].observed_at is None and any("timezone" in w for w in q.warnings)
    assert any("editable" in w for w in q.warnings)


def test_exif_truncation_fuzz_never_crashes():
    good = si.jpeg_with_gps()
    for cut in range(0, len(good), 3):
        try:
            geo.parse_jpeg_exif(good[:cut])
        except parsers.IngestError:
            pass  # a clean rejection is the only acceptable failure mode
    with pytest.raises(parsers.IngestError):
        geo.parse_jpeg_exif(b"not a jpeg")


def test_geotiff_metadata_crs_bounds_and_layer():
    p = geo.parse_geotiff(si.geotiff(w=4, h=4, epsg=4326, x0=2.0, y0=49.0, px=0.001))
    d = p.observations[0].data
    assert d["crs"] == "EPSG:4326" and d["width"] == 4
    assert d["bounds"] == pytest.approx({"min_x": 2.0, "max_x": 2.004, "min_y": 48.996, "max_y": 49.0})
    assert d["approx_pixel_size_m"] == pytest.approx(111.32, rel=1e-3) and p.layers[0]["precision_class"] == "COARSE"
    assert "licence" in d and "UNKNOWN" in d["licence"] and any("reprojection" in w for w in p.warnings)
    utm = geo.parse_geotiff(si.geotiff(epsg=32631, x0=500000, y0=5500000, px=2)).layers[0]
    assert utm["coordinate_system"] == "EPSG:32631" and utm["precision_class"] == "FINE"  # source CRS preserved
    with pytest.raises(parsers.IngestError):
        geo.parse_geotiff(si.geotiff(crs_keys=False))


def _png_with_filter(arr, ftype):
    h, w, ch = arr.shape
    rows, prev = [], np.zeros(w * ch, dtype=np.int32)
    for y in range(h):
        cur = arr[y].reshape(-1).astype(np.int32)
        out = np.zeros_like(cur)
        for i in range(len(cur)):
            a = cur[i - ch] if i >= ch else 0
            b = prev[i]
            c = prev[i - ch] if i >= ch else 0
            if ftype == 0:
                pred = 0
            elif ftype == 1:
                pred = a
            elif ftype == 2:
                pred = b
            elif ftype == 3:
                pred = (a + b) >> 1
            else:
                pa, pb, pc = abs(b - c), abs(a - c), abs(a + b - 2 * c)
                pred = a if pa <= pb and pa <= pc else (b if pb <= pc else c)
            out[i] = (cur[i] - pred) % 256
        rows.append(bytes([ftype]) + out.astype(np.uint8).tobytes())
        prev = cur
    raw = b"".join(rows)

    def chunk(t, d):
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)
    ctype = {1: 0, 2: 4, 3: 2, 4: 6}[ch]
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, ctype, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b""))


@pytest.mark.parametrize("ftype", [0, 1, 2, 3, 4])
@pytest.mark.parametrize("ch", [1, 3, 4])
def test_png_decoder_handles_every_filter_type(ftype, ch):
    arr = np.random.default_rng(ftype * 10 + ch).integers(0, 256, size=(9, 13, ch), dtype=np.uint8)
    assert np.array_equal(geo.decode_png(_png_with_filter(arr, ftype)), arr)


def test_png_rejects_corruption_and_limits():
    good = geo.encode_png(np.zeros((8, 8, 3), dtype=np.uint8))
    bad = bytearray(good)
    bad[40] ^= 0xFF
    for blob in (bytes(bad), good[:30], b"nope", geo.encode_png(np.zeros((1100, 1100), dtype=np.uint8))):
        with pytest.raises(parsers.IngestError):
            geo.decode_png(blob)


def test_change_detection_boxes_the_change_and_refuses_to_interpret():
    before, after = si.png_pair(64, 48, (20, 10, 30, 20))
    r = geo.change_detection(before, after, 30)
    assert r["bounding_box"] == {"x0": 20, "y0": 10, "x1": 29, "y1": 19} and r["changed_pixels"] == 100
    assert "NOT a verified real-world event" in r["interpretation"]
    assert geo.decode_png(r["_png"]).shape == (48, 64, 3)
    assert geo.change_detection(before, before, 30)["bounding_box"] is None
    other, _ = si.png_pair(32, 32)
    with pytest.raises(parsers.IngestError, match="sizes differ"):
        geo.change_detection(before, other)


async def test_geoint_api_flow_points_layers_change_and_export_redaction(api):
    cid = await case(api)
    j = (await imp(api, cid, "photo.jpg", si.jpeg_with_gps(48.85841, 2.29451))).json()
    assert j["discipline"] == "GEOINT" and j["kind"] == "jpeg_exif"
    pts = (await api.get(f"/api/v1/cases/{cid}/geo/points")).json()
    assert pts["items"][0]["lat"] == pytest.approx(48.85841, abs=1e-5) and "OpenStreetMap" in pts["attribution"]
    assert pts["items"][0]["accuracy_m"] is None
    await imp(api, cid, "dem.tif", si.geotiff())
    lay = (await api.get(f"/api/v1/cases/{cid}/geo/layers")).json()["items"]
    assert lay[0]["crs"] == "EPSG:4326" and lay[0]["precision_class"] == "COARSE"
    b, a = si.png_pair()
    eb = (await imp(api, cid, "before.png", b, kind="auto")).status_code
    assert eb == 422  # PNG is not an importable observation kind; it is stored as plain evidence instead
    e1 = (await api.post(f"/api/v1/cases/{cid}/evidence/import?filename=b.png&consent_confirmed=true", content=b)).json()
    e2 = (await api.post(f"/api/v1/cases/{cid}/evidence/import?filename=a.png&consent_confirmed=true", content=a)).json()
    ch = (await api.post(f"/api/v1/cases/{cid}/geo/change", json={"before_evidence_id": e1["id"], "after_evidence_id": e2["id"]})).json()
    assert ch["derived_from"] == [e1["id"], e2["id"]] and ch["changed_pixels"] == 100
    mask = (await api.get(f"/api/v1/evidence/{ch['mask_evidence_id']}")).json()
    assert mask["integrity_verified"] and mask["chain_of_custody"][0]["event"] == "derived"
    # exports: coordinates rounded by default and restricted observation excluded; exact only on explicit request
    rep = (await api.post(f"/api/v1/cases/{cid}/reports", json={"format": "json"})).json()
    data = json.loads((api.app.state.core.settings.export_dir / rep["file"]).read_text())
    assert not any(o["kind"] == "geo.exif_position" for o in data["observations"])
    assert "48.85841" not in json.dumps(data)
    full = (await api.post(f"/api/v1/cases/{cid}/reports", json={"format": "json", "include_sensitive": True})).json()
    fdata = json.loads((api.app.state.core.settings.export_dir / full["file"]).read_text())
    assert any(o["kind"] == "geo.exif_position" for o in fdata["observations"]) and "48.85841" in json.dumps(fdata)
    # cross-case evidence is rejected for change detection
    other = await case(api)
    assert (await api.post(f"/api/v1/cases/{other}/geo/change", json={"before_evidence_id": e1["id"], "after_evidence_id": e2["id"]})).status_code == 404


async def test_dimension_mismatch_via_api_is_422(api):
    cid = await case(api)
    b, _ = si.png_pair(64, 48)
    o, _ = si.png_pair(32, 32)
    e1 = (await api.post(f"/api/v1/cases/{cid}/evidence/import?filename=b.png&consent_confirmed=true", content=b)).json()
    e2 = (await api.post(f"/api/v1/cases/{cid}/evidence/import?filename=o.png&consent_confirmed=true", content=o)).json()
    r = await api.post(f"/api/v1/cases/{cid}/geo/change", json={"before_evidence_id": e1["id"], "after_evidence_id": e2["id"]})
    assert r.status_code == 422 and "sizes differ" in r.json()["message"]


# ================================================================== CYBINT ================================================
@pytest.mark.parametrize("ng", [False, True])
def test_pcap_and_pcapng_metadata(ng):
    p = net.parse_pcap(si.pcap(ng))
    d = p.observations[0].data
    assert d["packets"] == 4 and d["flows_total"] == 3  # the DNS query and its reply are one bidirectional flow
    assert {"name": "tracker.example.net", "type": "A", "count": 1} in d["dns_queries"]
    assert d["dns_answers"]["tracker.example.net"] == ["203.0.113.7"]
    assert d["tls_sni"] == [{"name": "secure.example.net", "count": 1}]
    assert d["http_hosts_cleartext"] == [{"name": "plain.example.net", "count": 1}]
    assert d["first_packet"].startswith("2023-11-14T22:13:20")
    rel = {(r.from_key, r.to_key, r.relation_type) for r in p.relationships}
    assert (("ip", "192.168.1.10"), ("domain", "secure.example.net"), "requested_tls_server_name") in rel
    assert (("domain", "tracker.example.net"), ("ip", "203.0.113.7"), "resolved_to_in_capture") in rel
    assert p.observations[0].sensitivity == "RESTRICTED" and "authorised" in " ".join(p.warnings)


def test_pcap_corruption_is_rejected_cleanly():
    good = si.pcap()
    for blob in (b"", good[:10], good[:60], b"\xd4\xc3\xb2\xa1" + b"\x00" * 20, good[:-5]):
        with pytest.raises(parsers.IngestError):
            net.parse_pcap(blob)
    for cut in range(0, len(good), 17):  # fuzz: only IngestError may escape
        try:
            net.parse_pcap(good[:cut])
        except parsers.IngestError:
            pass


def test_no_live_capture_or_active_networking_code_in_importers():
    forbidden = re.compile(r"\b(scapy|pyshark|pcapy|AF_PACKET|SOCK_RAW|socket\.|subprocess|os\.system|ctypes|winpcap|npcap)\b")
    for mod in ("net.py", "tech.py", "geo.py", "telemetry.py", "fin.py", "parsers.py"):
        text = re.sub(r'""".*?"""', "", (SRC / "ingest" / mod).read_text(), flags=re.DOTALL)  # docstrings may mention the words
        code = " ".join(line.split("#")[0] for line in text.splitlines())
        hits = forbidden.findall(code)
        assert not hits, (mod, hits)


def test_stix_import_extracts_iocs_and_labels_attribution_as_reported():
    p = net.parse_stix(si.stix_bundle())
    keys = {(e.type, e.key) for e in p.entities}
    assert ("domain", "evil.example.net") in keys and ("ip", "203.0.113.50") in keys
    assert ("hash", "aaaa000000000000000000000000000000000000000000000000000000000001") in keys
    assert ("malware", "ExampleRAT") in keys and ("threat_actor", "ACTOR-X") in keys
    uses = [r for r in p.relationships if r.relation_type == "uses"]
    assert uses and "not verified" in uses[0].reason and "asserted by the STIX producer" in uses[0].reason
    assert any("skipped" in w for w in p.warnings) and p.summary["skipped"] == 1
    ind = next(o for o in p.observations if o.kind == "cti.indicator")
    assert ind.data["producer_confidence"] == 85 and "not independently verified" in ind.data["note"] and ind.confidence == "low"
    for bad in (b"[]", b'{"type":"bundle"}', b"nope", b'{"type":"bundle","objects":[{"id":"x"}]}'):
        with pytest.raises(parsers.IngestError):
            net.parse_stix(bad)


def test_stix_pattern_extractor_edge_cases():
    assert net.extract_pattern_iocs("[url:value = 'http://a.example/x']") == [("url", "http://a.example/x")]
    assert net.extract_pattern_iocs("[email-addr:value = 'a@b.example']") == [("email", "a@b.example")]
    assert net.extract_pattern_iocs("[file:name = 'x.exe']") == []
    assert net.extract_pattern_iocs("garbage") == [] and net.extract_pattern_iocs("") == []


async def test_cyber_api_import_graph_and_stix_export_is_deterministic_and_filtered(api):
    cid = await case(api)
    r = await imp(api, cid, "cap.pcap", si.pcap())
    assert r.status_code == 201 and r.json()["discipline"] == "CYBINT"
    assert (await imp(api, cid, "bundle.stix.json", si.stix_bundle())).status_code == 201
    ents = (await api.get(f"/api/v1/cases/{cid}/entities?limit=1000")).json()["items"]
    assert {e["key"] for e in ents} >= {"192.168.1.10", "secure.example.net", "evil.example.net"}
    g = (await api.get(f"/api/v1/cases/{cid}/graph")).json()
    assert g["edges"] and all(e["status"] == "unverified" and e["evidence_ids"] for e in g["edges"])
    a = (await api.get(f"/api/v1/cases/{cid}/export/stix")).json()
    b = (await api.get(f"/api/v1/cases/{cid}/export/stix")).json()
    assert [o["id"] for o in a["objects"] if o["type"] != "bundle"] == [o["id"] for o in b["objects"] if o["type"] != "bundle"]
    sid = re.compile(r"^[a-z0-9-]+--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
    assert all(sid.match(o["id"]) for o in a["objects"]) and a["type"] == "bundle"
    rel = [o for o in a["objects"] if o["type"] == "relationship"]
    ids = {o["id"] for o in a["objects"]}
    assert rel and all(o["source_ref"] in ids and o["target_ref"] in ids for o in rel)
    assert all(o["x_osintcc_status"] in ("unverified", "corroborated", "manual") for o in rel)
    types = {o["type"] for o in a["objects"]}
    assert {"malware", "threat-actor", "domain-name"} <= types
    assert any(o["relationship_type"] == "uses" for o in rel)  # actor -> malware stays a valid SDO relationship
    assert all(o["relationship_type"] == "related-to" for o in rel if o["relationship_type"] not in ("uses", "resolves-to"))
    assert not any(o.get("value") == "192.168.1.10" for o in a["objects"])  # RESTRICTED pcap entities are not exported


# ================================================================== TECHINT ===============================================
def test_cyclonedx_and_spdx_components_and_dependencies():
    p = tech.parse_cyclonedx(si.cyclonedx())
    assert {e.display for e in p.entities} >= {"openssl 1.1.1k", "busybox 1.31.1", "widget-fw 2.0.1"}
    deps = {(r.from_key[1], r.to_key[1]) for r in p.relationships if r.relation_type == "depends_on"}
    assert ("busybox@1.31.1", "pkg:generic/openssl@1.1.1k") in deps
    assert any(r.relation_type == "contains" for r in p.relationships)
    comp = p.observations[0].data["components"]
    assert next(c for c in comp if c["name"] == "openssl")["licenses"] == ["Apache-2.0"]
    s = tech.parse_cyclonedx(si.spdx())
    assert s.observations[0].data["format"] == "SPDX" and len(s.relationships) == 1
    for bad in (b"{}", b"[]", b"nope", json.dumps({"bomFormat": "CycloneDX", "components": []}).encode()):
        with pytest.raises(parsers.IngestError):
            tech.parse_cyclonedx(bad)


def test_firmware_static_analysis_records_markers_not_secrets_and_never_executes():
    p = tech.parse_firmware(si.firmware())
    d = p.observations[0].data
    sigs = {(s["signature"], s["offset"]) for s in d["signatures"]}
    assert ("elf", 0) in sigs and any(s == "gzip" for s, _ in sigs)
    assert d["entropy_overall"] > 7.0 and d["entropy_blocks_64k"]
    assert "BusyBox v1.31.1" in d["software_versions"] and "http://update.vendor.example/fw.bin" in d["urls"]
    assert "support@vendor.example" in d["emails"] and "192.168.1.1" in d["ipv4_addresses"]
    assert d["credential_like_markers"].get("password") == 1
    assert "hunter2" not in json.dumps(d) and "never executed" in d["static_analysis_only"]
    with pytest.raises(parsers.IngestError):
        tech.parse_firmware(b"tiny")


async def test_techint_api_import_and_hostile_binary_cannot_run(api, settings):
    cid = await case(api)
    assert (await imp(api, cid, "widget.cdx.json", si.cyclonedx())).status_code == 201
    r = await imp(api, cid, "dropper.bin", b"MZ\x90\x00" + b"\x00" * 100 + b"cmd.exe /c calc")
    assert r.status_code == 201
    ev = next(settings.vault_dir.rglob(r.json()["sha256"]))
    assert ev.stat().st_mode & 0o111 == 0 or sys.platform == "win32"  # stored non-executable on POSIX; inert bytes anywhere
    assert (await api.get(f"/api/v1/cases/{cid}/observations?discipline=TECHINT")).json()["total"] == 2


# ================================================================== FISINT / ELINT =======================================
def test_ccsds_counts_apids_and_detects_sequence_gaps():
    p = telemetry.parse_ccsds(si.ccsds(gap=True))
    a = p.observations[0].data["apids"]
    assert p.observations[0].data["packets"] == 8 and a["100"]["packets"] == 5 and a["100"]["gaps"] == 1 and a["200"]["gaps"] == 0
    assert any("gaps" in w for w in p.warnings) and "not interpreted" in p.observations[0].data["decoding"]
    assert not any("gaps" in w for w in telemetry.parse_ccsds(si.ccsds(gap=False)).warnings)
    for bad in (b"", b"\x00\x01", si.ccsds()[:-3], b"\xe0\x00\x00\x00\x00\x01\x00\x00"):
        with pytest.raises(parsers.IngestError):
            telemetry.parse_ccsds(bad)


def test_telemetry_golden_calibration():
    p = telemetry.parse_telemetry_csv(si.telemetry_csv(True)).observations[0].data["parameters"]["BATT_V"]
    assert p["calibrated"] and p["unit"] == "V" and p["eng_min"] == pytest.approx(10.0) and p["eng_max"] == pytest.approx(10.9)
    assert p["eng_mean"] == pytest.approx(10.45)
    raw = telemetry.parse_telemetry_csv(si.telemetry_csv(False))
    assert not raw.observations[0].data["parameters"]["BATT_V"]["calibrated"] and any("raw counts" in w for w in raw.warnings)


def test_pulse_trains_require_declared_synthetic_or_owned_provenance():
    st = telemetry.parse_pulses(si.pulses("stable")).observations[0].data
    assert st["pri_pattern"] == "stable" and st["pri_us_median"] == pytest.approx(1000.0) and st["freq_mhz_median"] == 9400.0
    sg = telemetry.parse_pulses(si.pulses("staggered")).observations[0].data
    assert sg["pri_pattern"] == "staggered/multi-level" and "no emitter identification" in sg["identification"]
    assert telemetry.parse_pulses(si.pulses("stable")).access_class == "SIMULATION"
    assert telemetry.parse_pulses(si.pulses("stable", "owned_lab")).access_class == "OWNED_AUTHORIZED"
    for prov in ("", "intercepted", "radar_site_17"):
        with pytest.raises(parsers.IngestError, match="provenance"):
            telemetry.parse_pulses(si.pulses("stable", prov))


async def test_fisint_elint_api_and_autodetect(api):
    cid = await case(api)
    assert (await imp(api, cid, "tlm.ccsds", si.ccsds())).json()["discipline"] == "FISINT"
    assert (await imp(api, cid, "run1.tlm.csv", si.telemetry_csv())).json()["kind"] == "telemetry_csv"
    assert (await imp(api, cid, "train.pulses.csv", si.pulses())).json()["discipline"] == "ELINT"
    rej = await imp(api, cid, "x.pulses.csv", si.pulses(provenance="intercepted"))
    assert rej.status_code == 422 and "recordings of third-party emitters" in rej.json()["message"]
    with api.app.state.core.sm() as db:
        a = db.scalars(select(AuditEvent).where(AuditEvent.action == "ingest.rejected")).all()
        assert a and a[-1].decision == "deny"


# ================================================================== FININT ================================================
def test_edgar_uses_cik_identity_and_cites_filings():
    p = fin.parse_edgar(si.edgar())
    assert [e.key for e in p.entities if e.type == "company"] == ["cik:0000320193"]
    flings = [r for r in p.relationships if r.relation_type == "filed"]
    assert len(flings) == 3 and "https://www.sec.gov/Archives/edgar/data/320193/000032019324000001/a.htm" in flings[0].reason
    assert p.observations[0].confidence == "high" and "CIK" in p.observations[0].data["identity_note"]
    for bad in (b"{}", b"nope", json.dumps({"cik": "1", "filings": {"recent": {"accessionNumber": ["x"], "form": []}}}).encode()):
        with pytest.raises(parsers.IngestError):
            fin.parse_edgar(bad)


async def test_same_name_different_cik_are_never_merged(api):
    cid = await case(api)
    await imp(api, cid, "a.submissions.json", si.edgar(320193, "Same Name Inc"))
    await imp(api, cid, "b.submissions.json", si.edgar(999999, "Same Name Inc"))
    comps = (await api.get(f"/api/v1/cases/{cid}/entities?type=company")).json()["items"]
    assert {c["key"] for c in comps} == {"cik:0000320193", "cik:0000999999"}
    edges = (await api.get(f"/api/v1/cases/{cid}/graph")).json()["edges"]
    assert edges and all(e["type"] == "filed" and e["evidence_ids"] for e in edges)  # relationship rests on a filing record


def test_chain_transfers_are_pseudonymous_edges():
    p = fin.parse_chain_csv(si.chain_csv())
    assert {e.type for e in p.entities} == {"crypto_address"}
    pair = next(r for r in p.relationships if r.from_key[1].endswith("001"))
    assert "2 transfer(s), total 2 BTC" in pair.reason
    assert "do not identify a person" in p.observations[0].data["note"] or "does not identify a person" in p.observations[0].data["note"]
    for bad in (b"a,b\n1,2", b"txid,from,to,amount\nt,short,short,1", b"txid,from,to,amount\nt,aaaaaaaaaaaa,bbbbbbbbbbbb,-1"):
        with pytest.raises(parsers.IngestError):
            fin.parse_chain_csv(bad)


async def test_sanctions_licence_gate_blocks_and_audits(api, settings):
    cid = await case(api)
    for kw in ({}, {"license_basis": "free_code_is_fine", "licensor": "X"}, {"license_basis": "noncommercial"}):
        r = await imp(api, cid, "list.csv", si.sanctions_csv(), kind="sanctions_csv", **kw)
        assert r.status_code == 403 and r.json()["code"] == "license_blocked"
    with api.app.state.core.sm() as db:
        assert db.scalar(select(func.count()).select_from(Observation)) == 0 and db.scalar(select(func.count()).select_from(Evidence)) == 0
        assert db.scalars(select(AuditEvent).where(AuditEvent.action == "ingest.license_blocked")).all()
    assert not any(p.is_file() for p in settings.vault_dir.rglob("*"))  # blocked before anything is stored
    ok = await imp(api, cid, "list.csv", si.sanctions_csv(), kind="sanctions_csv", license_basis="noncommercial", licensor="TestSource")
    assert ok.status_code == 201 and ok.json()["observations_added"] == 2


async def test_sanctions_screening_proposes_but_never_merges_or_labels(api):
    cid = await case(api)
    await imp(api, cid, "x.submissions.json", si.edgar(1234, "Example Holdings Inc"))
    await imp(api, cid, "y.submissions.json", si.edgar(5678, "Totally Different Corp"))
    assert (await api.post(f"/api/v1/cases/{cid}/sanctions/screen", json={})).status_code == 409  # no list yet
    await imp(api, cid, "list.csv", si.sanctions_csv(), kind="sanctions_csv", license_basis="public_domain", licensor="TestSource")
    before = (await api.get(f"/api/v1/cases/{cid}/entities?limit=1000")).json()["total"]
    r = (await api.post(f"/api/v1/cases/{cid}/sanctions/screen", json={})).json()
    assert r["proposals_created"] == 1 and "not findings" in r["note"]
    assert r["possible_matches"][0]["entity"].startswith("Example Holdings Inc")
    again = (await api.post(f"/api/v1/cases/{cid}/sanctions/screen", json={})).json()
    assert again["proposals_created"] == 0  # idempotent
    assert (await api.get(f"/api/v1/cases/{cid}/entities?limit=1000")).json()["total"] == before
    with api.app.state.core.sm() as db:
        props = db.scalars(select(GraphProposal)).all()
        assert len(props) == 1 and props[0].status == "pending" and "similarity ONLY" in props[0].reason
    assert fin.normalise_name("The Example-Holdings, Ltd.") == "example holdings"


# ================================================================== re-analysis endpoints + detection =====================
async def test_spectrogram_and_series_endpoints_are_bounded_and_kind_checked(api):
    cid = await case(api)
    sig = (await imp(api, cid, "t.sigmf", synthetic.sigmf_archive(tone_hz=2000.0))).json()
    csvr = (await imp(api, cid, "s.csv", synthetic.sensor_csv())).json()
    r = await api.post(f"/api/v1/cases/{cid}/signal/spectrogram", json={"evidence_id": sig["evidence_id"], "nfft": 1024})
    top = r.json()["spectrum"]["peaks"][0]
    assert r.status_code == 200 and abs(top["offset_hz"] - 2000.0) <= 48000 / 1024
    for bad in ({"nfft": 100}, {"nfft": 1 << 20}, {"nfft": 64, "max_peaks": 99}):
        assert (await api.post(f"/api/v1/cases/{cid}/signal/spectrogram", json={"evidence_id": sig["evidence_id"], **bad})).status_code == 422
    assert (await api.post(f"/api/v1/cases/{cid}/signal/spectrogram", json={"evidence_id": csvr["evidence_id"]})).status_code == 422
    s = await api.post(f"/api/v1/cases/{cid}/sensor/series/analyze", json={"evidence_id": csvr["evidence_id"], "z_threshold": 3.0})
    assert s.status_code == 200 and s.json()["result"]["anomaly_intervals"]
    assert (await api.post(f"/api/v1/cases/{cid}/sensor/series/analyze", json={"evidence_id": csvr["evidence_id"], "z_threshold": 0.5})).status_code == 422


async def test_autodetect_covers_new_kinds_and_unknown_is_422(api):
    cid = await case(api)
    cases = {"p.pcap": si.pcap(), "p.pcapng": si.pcap(True), "x.jpg": si.jpeg_with_gps(), "g.tif": si.geotiff(),
             "bom.sbom.json": si.cyclonedx(), "fw.bin": si.firmware(), "c.chain.csv": si.chain_csv()}
    for name, data in cases.items():
        r = await imp(api, cid, name, data)
        assert r.status_code == 201, (name, r.text)
    assert (await imp(api, cid, "mystery.xyz", b"\x00\x01\x02\x03")).status_code == 422
    kinds = {o["kind"] for o in (await api.get(f"/api/v1/cases/{cid}/observations?limit=500")).json()["items"]}
    assert {"net.capture_summary", "geo.exif_position", "geo.raster_metadata", "sbom.components", "firmware.static_analysis",
            "fin.chain_transfers"} <= kinds
    hits = (await api.get(f"/api/v1/cases/{cid}/search", params={"q": "firmware.static_analysis"})).json()["items"]
    assert any(h["kind"] == "observation" for h in hits)
