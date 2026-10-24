"""SYNTHETIC fixtures for the intelligence importers. Fabricated byte-for-byte; no real recordings, captures or data."""
from __future__ import annotations

import io
import json
import struct

import numpy as np
from osintcc.ingest.geo import encode_png


# ---------------------------------------------------------------- TIFF / JPEG builders -------------------------------
def _ifd(entries, start: int, big: bool = False) -> bytes:
    """entries: (tag, type, count, data). Little-endian classic TIFF IFD with out-of-line values after the table."""
    entries = sorted(entries, key=lambda e: e[0])
    size = 2 + 12 * len(entries) + 4
    table, extra = b"", b""
    for tag, typ, count, data in entries:
        if len(data) <= 4:
            val = data.ljust(4, b"\x00")
        else:
            val = struct.pack("<I", start + size + len(extra))
            extra += data + (b"\x00" if len(data) % 2 else b"")
        table += struct.pack("<HHI", tag, typ, count) + val
    return struct.pack("<H", len(entries)) + table + struct.pack("<I", 0) + extra


def _rat(*pairs):
    return b"".join(struct.pack("<II", a, b) for a, b in pairs)


def jpeg_with_gps(lat=48.8584, lon=2.2945, alt=35, with_gps=True, hacc=None, gps_time=True) -> bytes:
    def dms(x):
        x = abs(x)
        d = int(x)
        m = int((x - d) * 60)
        s = round(((x - d) * 60 - m) * 60 * 10000)
        return _rat((d, 1), (m, 1), (s, 10000))
    gps = [(1, 2, 2, b"N\x00" if lat >= 0 else b"S\x00"), (2, 5, 3, dms(lat)),
           (3, 2, 2, b"E\x00" if lon >= 0 else b"W\x00"), (4, 5, 3, dms(lon)), (5, 1, 1, b"\x00"), (6, 5, 1, _rat((alt, 1)))]
    if gps_time:
        gps += [(7, 5, 3, _rat((12, 1), (30, 1), (15, 1))), (29, 2, 11, b"2024:05:01\x00")]
    if hacc is not None:
        gps.append((31, 5, 1, _rat((hacc, 1))))
    exif = [(0x9003, 2, 20, b"2024:05:01 14:30:15\x00")]
    ifd0_stub = [(0x010F, 2, 6, b"FakeCo\x00"), (0x0110, 2, 8, b"Model-X\x00"), (0x8769, 4, 1, b"\x00" * 4)]
    if with_gps:
        ifd0_stub.append((0x8825, 4, 1, b"\x00" * 4))
    n0 = len(_ifd(ifd0_stub, 8))
    exif_off = 8 + n0
    n_exif = len(_ifd(exif, exif_off))
    gps_off = exif_off + n_exif
    ifd0 = [(0x010F, 2, 6, b"FakeCo\x00"), (0x0110, 2, 8, b"Model-X\x00"), (0x8769, 4, 1, struct.pack("<I", exif_off))]
    if with_gps:
        ifd0.append((0x8825, 4, 1, struct.pack("<I", gps_off)))
    tiff = b"II*\x00" + struct.pack("<I", 8) + _ifd(ifd0, 8) + _ifd(exif, exif_off) + (_ifd(gps, gps_off) if with_gps else b"")
    app1 = b"Exif\x00\x00" + tiff
    return b"\xff\xd8" + b"\xff\xe1" + struct.pack(">H", len(app1) + 2) + app1 + b"\xff\xd9"


def geotiff(w=4, h=4, epsg=4326, x0=2.0, y0=49.0, px=0.001, crs_keys=True) -> bytes:
    n_strip = w * h
    entries = [(256, 3, 1, struct.pack("<H", w)), (257, 3, 1, struct.pack("<H", h)), (258, 3, 1, struct.pack("<H", 8)),
               (259, 3, 1, struct.pack("<H", 1)), (262, 3, 1, struct.pack("<H", 1)), (277, 3, 1, struct.pack("<H", 1)),
               (278, 3, 1, struct.pack("<H", h)), (279, 4, 1, struct.pack("<I", n_strip)),
               (273, 4, 1, struct.pack("<I", 0))]
    if crs_keys:
        keys = [1, 1, 0, 3, 1024, 0, 1, 2, 1025, 0, 1, 1, 2048, 0, 1, epsg]
        entries += [(33550, 12, 3, struct.pack("<3d", px, px, 0)), (33922, 12, 6, struct.pack("<6d", 0, 0, 0, x0, y0, 0)),
                    (34735, 3, len(keys), struct.pack(f"<{len(keys)}H", *keys))]
    ifd_len = len(_ifd(entries, 8))
    entries = [(t, ty, c, struct.pack("<I", 8 + ifd_len) if t == 273 else d) for t, ty, c, d in entries]
    return b"II*\x00" + struct.pack("<I", 8) + _ifd(entries, 8) + bytes(n_strip)


def png_pair(w=64, h=48, changed_box=(20, 10, 30, 20)):
    rng = np.random.default_rng(5)
    base = rng.integers(90, 120, size=(h, w, 3), dtype=np.uint8)
    after = base.copy()
    x0, y0, x1, y1 = changed_box
    after[y0:y1, x0:x1] = 250
    return encode_png(base), encode_png(after)


# ---------------------------------------------------------------- network ------------------------------------------
def _eth_ip_udp(src, dst, sport, dport, payload):
    udp = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0, bytes(map(int, src.split("."))),
                     bytes(map(int, dst.split(".")))) + udp
    return b"\x00" * 12 + b"\x08\x00" + ip


def _eth_ip_tcp(src, dst, sport, dport, payload):
    tcp = struct.pack(">HHIIBBHHH", sport, dport, 1, 0, 5 << 4, 0x18, 8192, 0, 0) + payload
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0, bytes(map(int, src.split("."))),
                     bytes(map(int, dst.split(".")))) + tcp
    return b"\x00" * 12 + b"\x08\x00" + ip


def _qname(name):
    return b"".join(bytes([len(x)]) + x.encode() for x in name.split(".")) + b"\x00"


def _client_hello(sni: str) -> bytes:
    name = sni.encode()
    sn = struct.pack(">HBH", len(name) + 3, 0, len(name)) + name
    ext = struct.pack(">HH", 0, len(sn)) + sn
    body = b"\x03\x03" + b"\x11" * 32 + b"\x00" + struct.pack(">H", 2) + b"\x13\x01" + b"\x01\x00" + struct.pack(">H", len(ext)) + ext
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs


def pcap(ng=False) -> bytes:
    pk = []
    q = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + _qname("tracker.example.net") + struct.pack(">HH", 1, 1)
    r = (struct.pack(">HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0) + _qname("tracker.example.net") + struct.pack(">HH", 1, 1)
         + b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + bytes([203, 0, 113, 7]))
    pk.append((1700000000.0, _eth_ip_udp("192.168.1.10", "192.168.1.1", 40000, 53, q)))
    pk.append((1700000000.1, _eth_ip_udp("192.168.1.1", "192.168.1.10", 53, 40000, r)))
    pk.append((1700000001.0, _eth_ip_tcp("192.168.1.10", "203.0.113.7", 50000, 443, _client_hello("secure.example.net"))))
    pk.append((1700000002.0, _eth_ip_tcp("192.168.1.10", "198.51.100.9", 50001, 80,
                                         b"GET / HTTP/1.1\r\nHost: plain.example.net\r\n\r\n")))
    if not ng:
        out = b"\xd4\xc3\xb2\xa1" + struct.pack("<HHiIII", 2, 4, 0, 0, 65535, 1)
        for ts, p in pk:
            out += struct.pack("<IIII", int(ts), int((ts % 1) * 1e6), len(p), len(p)) + p
        return out

    def blk(t, body):
        body += b"\x00" * (-len(body) % 4)
        return struct.pack("<II", t, len(body) + 12) + body + struct.pack("<I", len(body) + 12)
    out = blk(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    out += blk(1, struct.pack("<HHI", 1, 0, 65535))
    for ts, p in pk:
        t = int(ts * 1e6)
        out += blk(6, struct.pack("<IIIII", 0, t >> 32, t & 0xFFFFFFFF, len(p), len(p)) + p)
    return out


def stix_bundle() -> bytes:
    u = lambda n: f"00000000-0000-4000-8000-{n:012d}"
    objs = [
        {"type": "indicator", "spec_version": "2.1", "id": f"indicator--{u(1)}", "created": "2024-01-01T00:00:00Z",
         "pattern": "[domain-name:value = 'Evil.Example.NET'] OR [ipv4-addr:value = '203.0.113.50']", "pattern_type": "stix",
         "valid_from": "2024-01-01T00:00:00Z", "confidence": 85, "created_by_ref": f"identity--{u(9)}", "name": "C2 infra"},
        {"type": "indicator", "spec_version": "2.1", "id": f"indicator--{u(2)}", "created": "2024-01-01T00:00:00Z",
         "pattern": "[file:hashes.'SHA-256' = 'AAAA000000000000000000000000000000000000000000000000000000000001']",
         "pattern_type": "stix", "valid_from": "2024-01-02T00:00:00Z"},
        {"type": "malware", "spec_version": "2.1", "id": f"malware--{u(3)}", "name": "ExampleRAT", "created": "2024-01-01T00:00:00Z"},
        {"type": "threat-actor", "spec_version": "2.1", "id": f"threat-actor--{u(4)}", "name": "ACTOR-X", "created": "2024-01-01T00:00:00Z"},
        {"type": "relationship", "id": f"relationship--{u(5)}", "relationship_type": "indicates", "source_ref": f"indicator--{u(1)}",
         "target_ref": f"malware--{u(3)}", "created_by_ref": f"identity--{u(9)}"},
        {"type": "relationship", "id": f"relationship--{u(6)}", "relationship_type": "uses", "source_ref": f"threat-actor--{u(4)}",
         "target_ref": f"malware--{u(3)}"},
        {"type": "indicator", "id": "not-a-valid-id", "pattern": "[domain-name:value = 'skipped.example']"},
    ]
    return json.dumps({"type": "bundle", "id": f"bundle--{u(0)}", "objects": objs}).encode()


# ---------------------------------------------------------------- tech / telemetry / pulses ---------------------------
def cyclonedx() -> bytes:
    return json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.5", "metadata": {"component": {"name": "widget-fw", "version": "2.0.1"}},
                       "components": [
                           {"type": "library", "name": "openssl", "version": "1.1.1k", "bom-ref": "a", "purl": "pkg:generic/openssl@1.1.1k",
                            "licenses": [{"license": {"id": "Apache-2.0"}}], "hashes": [{"alg": "SHA-256", "content": "ab" * 32}]},
                           {"type": "library", "name": "zlib", "version": "1.2.11", "bom-ref": "b"},
                           {"type": "library", "name": "busybox", "version": "1.31.1", "bom-ref": "c"}],
                       "dependencies": [{"ref": "c", "dependsOn": ["a", "b"]}]}).encode()


def spdx() -> bytes:
    return json.dumps({"spdxVersion": "SPDX-2.3", "packages": [
        {"SPDXID": "SPDXRef-A", "name": "alpha", "versionInfo": "1.0", "licenseConcluded": "MIT"},
        {"SPDXID": "SPDXRef-B", "name": "beta", "versionInfo": "2.0"}],
        "relationships": [{"spdxElementId": "SPDXRef-A", "relationshipType": "DEPENDS_ON", "relatedSpdxElement": "SPDXRef-B"}]}).encode()


def firmware() -> bytes:
    rng = np.random.default_rng(11)
    text = (b"\x00" * 64 + b"BusyBox v1.31.1 (2021-01-01)\x00OpenSSL 1.1.1k  25 Mar 2021\x00"
            b"http://update.vendor.example/fw.bin\x00support@vendor.example\x00gateway 192.168.1.1\x00"
            b"password=hunter2hunter2\x00Linux version 4.14.180-fake\x00")
    gz = b"\x1f\x8b\x08\x00" + b"\x00" * 12
    return b"\x7fELF" + b"\x00" * 60 + text + b"\x00" * 3000 + gz + rng.integers(0, 256, 70000, dtype=np.uint8).tobytes()


def ccsds(gap=True) -> bytes:
    def pkt(apid, seq, payload=b"\x00\x01\x02\x03"):
        return struct.pack(">HHH", (0 << 13) | (0 << 12) | (1 << 11) | apid, (3 << 14) | seq, len(payload) - 1) + payload
    seqs = [0, 1, 2, 4, 5] if gap else [0, 1, 2, 3, 4]
    return b"".join(pkt(100, s) for s in seqs) + b"".join(pkt(200, s, b"\xff" * 8) for s in range(3))


def telemetry_csv(calibrated=True) -> bytes:
    rows = ["timestamp,parameter,raw,unit,slope,offset" if calibrated else "timestamp,parameter,raw"]
    for i in range(10):
        t = f"2026-01-01T00:00:{i:02d}Z"
        rows.append(f"{t},BATT_V,{1000 + i * 10},V,0.01,0.0" if calibrated else f"{t},BATT_V,{1000 + i * 10}")
    return "\n".join(rows).encode()


def pulses(pattern="stable", provenance="synthetic") -> bytes:
    toa, t = [], 0.0
    for i in range(60):
        toa.append(t)
        t += 1000.0 if pattern == "stable" else (1000.0 if i % 2 else 1500.0)
    head = f"# provenance: {provenance}\n" if provenance else ""
    rows = [f"{x:.3f},1.0,9400.0,-40.0" for x in toa]
    return (head + "toa_us,pw_us,freq_mhz,amp_db\n" + "\n".join(rows)).encode()


# ---------------------------------------------------------------- finance ------------------------------------------
def edgar(cik=320193, name="Example Corp", n=3) -> bytes:
    acc = [f"0000320193-24-{i:06d}" for i in range(1, n + 1)]
    return json.dumps({"cik": str(cik), "name": name, "sic": "3571", "sicDescription": "Electronic Computers",
                       "stateOfIncorporation": "CA", "tickers": ["EXMP"], "filings": {"recent": {
                           "accessionNumber": acc, "form": ["10-K", "8-K", "10-Q"][:n], "filingDate": ["2024-11-01", "2024-08-02", "2024-05-03"][:n],
                           "primaryDocument": ["a.htm", "b.htm", "c.htm"][:n]}}}).encode()


def chain_csv() -> bytes:
    a, b, c = "bc1qexampleaddress000000001", "bc1qexampleaddress000000002", "bc1qexampleaddress000000003"
    rows = ["txid,time,from,to,amount,asset", f"t1,2024-01-01T00:00:00Z,{a},{b},1.5,BTC", f"t2,2024-01-02T00:00:00Z,{a},{b},0.5,BTC",
            f"t3,2024-01-03T00:00:00Z,{b},{c},1.9,BTC"]
    return "\n".join(rows).encode()


def sanctions_csv() -> bytes:
    return (b"id,name,aliases,country,list_name,program\nS-1,Example Holdings Ltd,Exemplar Group;EX Holdings,XX,TESTLIST,PRG\n"
            b"S-2,Other Person,,YY,TESTLIST,PRG\n")


_ = io
