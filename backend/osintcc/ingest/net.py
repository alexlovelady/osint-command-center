"""CYBINT importers: offline PCAP/pcapng analysis and STIX 2.1 bundles (spec 21.1, 21.8 #7).

There is deliberately NO live-capture code in this module (no sockets, no interface enumeration): it only reads bytes
the analyst supplies from a network they own or are authorised to inspect.
"""
from __future__ import annotations

import ipaddress
import json
import re
import struct
import uuid
from collections import Counter
from datetime import UTC, datetime
from typing import Any

from .parsers import DETECTORS, PARSERS, EntityDraft, IngestError, Obs, ParsedIngest, RelDraft

MAX_PACKETS = 2_000_000
TOP_N = 200

_PCAP_MAGICS = {b"\xd4\xc3\xb2\xa1": ("<", 1e-6), b"\xa1\xb2\xc3\xd4": (">", 1e-6),
                b"\x4d\x3c\xb2\xa1": ("<", 1e-9), b"\xa1\xb2\x3c\x4d": (">", 1e-9)}


def _iter_pcap(data: bytes):
    magic = data[:4]
    if magic == b"\x0a\x0d\x0d\x0a":
        yield from _iter_pcapng(data)
        return
    if magic not in _PCAP_MAGICS:
        raise IngestError("not a pcap/pcapng file")
    e, res = _PCAP_MAGICS[magic]
    if len(data) < 24:
        raise IngestError("truncated pcap header")
    link = struct.unpack(e + "I", data[20:24])[0]
    pos = 24
    while pos + 16 <= len(data):
        sec, frac, incl, _orig = struct.unpack(e + "IIII", data[pos:pos + 16])
        if incl > 262144 or pos + 16 + incl > len(data):
            raise IngestError("truncated or corrupt packet record")
        yield link, sec + frac * res, data[pos + 16:pos + 16 + incl]
        pos += 16 + incl


def _iter_pcapng(data: bytes):
    pos, e, ifs = 0, "<", []
    while pos + 12 <= len(data):
        if pos == 0:
            bom = data[8:12]
            order = "<" if bom == b"\x4d\x3c\x2b\x1a" else (">" if bom == b"\x1a\x2b\x3c\x4d" else None)
            if order is None:
                raise IngestError("bad pcapng byte-order magic")
            e = order
        btype, blen = struct.unpack(e + "II", data[pos:pos + 8])
        if blen < 12 or blen % 4 or pos + blen > len(data):
            raise IngestError("corrupt pcapng block")
        body = data[pos + 8:pos + blen - 4]
        if btype == 1 and len(body) >= 8:
            link, res = struct.unpack(e + "H", body[:2])[0], 1e-6
            opts = body[8:]
            while len(opts) >= 4:
                code, ln = struct.unpack(e + "HH", opts[:4])
                if code == 0:
                    break
                if code == 9 and ln >= 1:
                    v = opts[4]
                    res = 2.0 ** -(v & 0x7F) if v & 0x80 else 10.0 ** -v
                opts = opts[4 + ((ln + 3) & ~3):]
            ifs.append((link, res))
        elif btype == 6 and len(body) >= 20:
            iid, th, tl, cap, _orig = struct.unpack(e + "IIIII", body[:20])
            if iid >= len(ifs) or cap > 262144 or 20 + cap > len(body):
                raise IngestError("corrupt pcapng packet block")
            link, res = ifs[iid]
            yield link, ((th << 32) | tl) * res, body[20:20 + cap]
        pos += blen


def _l3(link: int, pkt: bytes):
    if link == 1 and len(pkt) >= 14:
        et, off = struct.unpack(">H", pkt[12:14])[0], 14
        while et in (0x8100, 0x88A8) and len(pkt) >= off + 4:
            et, off = struct.unpack(">H", pkt[off + 2:off + 4])[0], off + 4
        return et, pkt[off:]
    if link == 113 and len(pkt) >= 16:
        return struct.unpack(">H", pkt[14:16])[0], pkt[16:]
    if link in (101, 12, 14) and pkt:
        v = pkt[0] >> 4
        return (0x0800 if v == 4 else 0x86DD if v == 6 else 0), pkt
    return 0, b""


def _dns_name(buf: bytes, off: int, depth: int = 0) -> tuple[str, int]:
    labels: list[str] = []
    jumped, end = False, off
    for _ in range(64):
        if off >= len(buf):
            raise IngestError("dns name overrun")
        ln = buf[off]
        if ln == 0:
            return ".".join(labels), (end if jumped else off + 1)
        if ln & 0xC0 == 0xC0:
            if depth > 4 or off + 1 >= len(buf):
                raise IngestError("dns pointer loop")
            ptr = ((ln & 0x3F) << 8) | buf[off + 1]
            if not jumped:
                end = off + 2
            name, _ = _dns_name(buf, ptr, depth + 1)
            return ".".join([*labels, name] if name else labels), end
        labels.append(buf[off + 1:off + 1 + ln].decode("ascii", "replace").lower())
        off += 1 + ln
    raise IngestError("dns name too long")


def _parse_dns(p: bytes) -> tuple[list[tuple[str, int]], list[tuple[str, str]], bool]:
    if len(p) < 12:
        return [], [], False
    is_response = bool(p[2] & 0x80)
    qd, an = struct.unpack(">HH", p[4:8])
    off, qs, ans = 12, [], []
    for _ in range(min(qd, 4)):
        name, off = _dns_name(p, off)
        qs.append((name, struct.unpack(">H", p[off:off + 2])[0]))
        off += 4
    for _ in range(min(an, 16)):
        name, off = _dns_name(p, off)
        typ, _cls, _ttl, rl = struct.unpack(">HHIH", p[off:off + 10])
        rd = p[off + 10:off + 10 + rl]
        if typ == 1 and rl == 4:
            ans.append((name, str(ipaddress.IPv4Address(rd))))
        elif typ == 28 and rl == 16:
            ans.append((name, str(ipaddress.IPv6Address(rd))))
        off += 10 + rl
    return qs, ans, is_response


def _sni(payload: bytes) -> str | None:
    try:
        if len(payload) < 48 or payload[0] != 0x16 or payload[5] != 0x01:
            return None
        pos = 9 + 2 + 32
        pos += 1 + payload[pos]
        pos += 2 + struct.unpack(">H", payload[pos:pos + 2])[0]
        pos += 1 + payload[pos]
        end = pos + 2 + struct.unpack(">H", payload[pos:pos + 2])[0]
        pos += 2
        while pos + 4 <= min(end, len(payload)):
            typ, ln = struct.unpack(">HH", payload[pos:pos + 4])
            if typ == 0 and ln >= 5:
                nl = struct.unpack(">H", payload[pos + 7:pos + 9])[0]
                return payload[pos + 9:pos + 9 + nl].decode("ascii", "replace").lower()
            pos += 4 + ln
    except (IndexError, struct.error):
        return None
    return None


_HOST = re.compile(rb"\r\nHost: ([A-Za-z0-9.\-:]{1,255})\r\n")


def parse_pcap(data: bytes) -> ParsedIngest:
    flows: dict[tuple, dict[str, Any]] = {}
    dns_q: Counter = Counter()
    dns_a: dict[str, set[str]] = {}
    snis: Counter = Counter()
    hosts: Counter = Counter()
    sni_by_src: dict[tuple[str, str], int] = Counter()
    n = 0
    first: float | None = None
    last = 0.0
    truncated = False
    for link, ts, pkt in _iter_pcap(data):
        n += 1
        if n > MAX_PACKETS:
            truncated = True
            break
        first, last = (ts if first is None else first), ts
        et, l3 = _l3(link, pkt)
        try:
            if et == 0x0800 and len(l3) >= 20:
                ihl = (l3[0] & 0x0F) * 4
                proto, src, dst = l3[9], str(ipaddress.IPv4Address(l3[12:16])), str(ipaddress.IPv4Address(l3[16:20]))
                l4 = l3[ihl:]
            elif et == 0x86DD and len(l3) >= 40:
                proto, src, dst = l3[6], str(ipaddress.IPv6Address(l3[8:24])), str(ipaddress.IPv6Address(l3[24:40]))
                l4 = l3[40:]
            else:
                continue
            sport = dport = 0
            payload = b""
            if proto in (6, 17) and len(l4) >= 8:
                sport, dport = struct.unpack(">HH", l4[:4])
                payload = l4[((l4[12] >> 4) * 4 if proto == 6 and len(l4) >= 20 else 8):]
            key = (proto, *sorted([(src, sport), (dst, dport)]))
            f = flows.setdefault(key, {"proto": {6: "tcp", 17: "udp", 1: "icmp"}.get(proto, str(proto)),
                                       "a": f"{key[1][0]}:{key[1][1]}", "b": f"{key[2][0]}:{key[2][1]}",
                                       "packets": 0, "bytes": 0, "first": ts, "last": ts})
            f["packets"] += 1
            f["bytes"] += len(pkt)
            f["last"] = ts
            if proto == 17 and 53 in (sport, dport) and payload:
                try:
                    qs, ans, is_resp = _parse_dns(payload)
                except (IngestError, struct.error, ValueError):
                    qs, ans, is_resp = [], [], False
                for name, qt in qs:
                    if not is_resp:  # a reply repeats the question section; count each query once
                        dns_q[(name, qt)] += 1
                for name, ip in ans:
                    dns_a.setdefault(name, set()).add(ip)
            elif proto == 6 and payload:
                s = _sni(payload)
                if s:
                    snis[s] += 1
                    sni_by_src[(src, s)] += 1
                m = _HOST.search(payload[:2048]) if payload[:4] in (b"GET ", b"POST", b"HEAD", b"PUT ") else None
                if m:
                    hosts[m.group(1).decode().lower()] += 1
        except (struct.error, ValueError, IndexError):
            continue
    if n == 0 or first is None:
        raise IngestError("capture contains no packets")
    top = sorted(flows.values(), key=lambda f: -f["bytes"])[:TOP_N]
    for f in top:
        f["first"] = datetime.fromtimestamp(f["first"], UTC).isoformat()
        f["last"] = datetime.fromtimestamp(f["last"], UTC).isoformat()
    qtypes = {1: "A", 28: "AAAA", 5: "CNAME", 15: "MX", 16: "TXT", 2: "NS"}
    summary = {"packets": n, "truncated_at_limit": truncated, "flows_total": len(flows), "flows_top": top,
               "first_packet": datetime.fromtimestamp(first, UTC).isoformat(),
               "last_packet": datetime.fromtimestamp(last, UTC).isoformat(),
               "dns_queries": [{"name": k[0], "type": qtypes.get(k[1], str(k[1])), "count": c}
                               for k, c in dns_q.most_common(TOP_N)],
               "dns_answers": {k: sorted(v) for k, v in list(dns_a.items())[:TOP_N]},
               "tls_sni": [{"name": k, "count": c} for k, c in snis.most_common(TOP_N)],
               "http_hosts_cleartext": [{"name": k, "count": c} for k, c in hosts.most_common(50)],
               "provenance": "analyst-supplied capture file; endpoints are NOT attributed to people or organisations"}
    p = ParsedIngest("pcap", "CYBINT", {"packets": n, "flows": len(flows), "dns": len(dns_q), "sni": len(snis)},
                     mime="application/vnd.tcpdump.pcap", access_class="OWNED_AUTHORIZED",
                     sensitivity="RESTRICTED")
    p.observations.append(Obs("CYBINT", "net.capture_summary", summary,
                              observed_at=datetime.fromtimestamp(first, UTC), confidence="medium",
                              sensitivity="RESTRICTED"))
    if truncated:
        p.warnings.append(f"Stopped after {MAX_PACKETS} packets.")
    p.warnings.append("Offline analysis only; no interface was read. Capture only networks you own or are authorised to inspect.")
    seen: set[tuple[str, str]] = set()

    def ent(t: str, k: str):
        if (t, k) not in seen and len(seen) < 600:
            seen.add((t, k))
            p.entities.append(EntityDraft(t, k, k))
        return (t, k) in seen
    for f in top[:100]:
        a, b = f["a"].rsplit(":", 1)[0], f["b"].rsplit(":", 1)[0]
        if ent("ip", a) and ent("ip", b) and a != b:
            p.relationships.append(RelDraft(("ip", a), ("ip", b), "observed_communicating_with",
                                            f"{f['proto']} flow in the supplied capture ({f['packets']} packets)"))
    for (src, name), _c in list(sni_by_src.items())[:100]:
        if ent("ip", src) and ent("domain", name):
            p.relationships.append(RelDraft(("ip", src), ("domain", name), "requested_tls_server_name",
                                            "TLS ClientHello SNI observed in the capture"))
    for name, ips in list(dns_a.items())[:100]:
        if ent("domain", name):
            for ip in sorted(ips)[:4]:
                if ent("ip", ip):
                    p.relationships.append(RelDraft(("domain", name), ("ip", ip), "resolved_to_in_capture",
                                                    "DNS answer observed in the capture (not independently verified)"))
    return p


# ------------------------------------------------------------------ STIX 2.1 ------------------------------------
_STIX_ID = re.compile(r"^[a-z][a-z0-9-]{1,}--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_CMP = re.compile(r"([a-z][a-z0-9-]*):([A-Za-z0-9_.'\-\"]+?)\s*=\s*'((?:[^'\\]|\\.)*)'")
_IOC_TYPE = {"domain-name": "domain", "ipv4-addr": "ip", "ipv6-addr": "ip", "url": "url", "email-addr": "email"}
MAX_STIX_OBJECTS = 20_000


def extract_pattern_iocs(pattern: str) -> list[tuple[str, str]]:
    out = []
    for typ, path, val in _CMP.findall(pattern or ""):
        val = val.replace("\\'", "'")
        if typ in _IOC_TYPE and path.strip("'\"") == "value":
            out.append((_IOC_TYPE[typ], val.lower() if typ == "domain-name" else val))
        elif typ == "file" and path.startswith("hashes."):
            out.append(("hash", val.lower()))
    return out


def parse_stix(data: bytes) -> ParsedIngest:
    try:
        bundle = json.loads(data)
    except ValueError as exc:
        raise IngestError("not valid JSON") from exc
    if not isinstance(bundle, dict) or bundle.get("type") != "bundle" or not isinstance(bundle.get("objects"), list):
        raise IngestError("not a STIX bundle (type must be 'bundle' with an objects list)")
    objs = bundle["objects"]
    if len(objs) > MAX_STIX_OBJECTS:
        raise IngestError(f"bundle exceeds {MAX_STIX_OBJECTS} objects")
    p = ParsedIngest("stix", "CYBINT", {}, mime="application/stix+json", access_class="IMPORTED")
    by_id: dict[str, tuple[str, str]] = {}
    skipped = 0
    seen: set[tuple[str, str]] = set()

    def add(t: str, k: str, d: str | None = None):
        if (t, k) not in seen:
            seen.add((t, k))
            p.entities.append(EntityDraft(t, k, d or k))
    counts: Counter = Counter()
    for o in objs:
        if not isinstance(o, dict) or not isinstance(o.get("id"), str) or not _STIX_ID.match(o["id"]) \
                or o.get("id", "").split("--")[0] != o.get("type"):
            skipped += 1
            continue
        t = o["type"]
        counts[t] += 1
        if t in ("malware", "threat-actor", "intrusion-set", "campaign", "tool"):
            nm = str(o.get("name", o["id"]))[:200]
            kind = t.replace("-", "_")
            add(kind, nm)
            by_id[o["id"]] = (kind, nm)
            p.observations.append(Obs("CYBINT", f"cti.{kind}", {"id": o["id"], "name": nm,
                                                                "description": str(o.get("description", ""))[:1000],
                                                                "producer": o.get("created_by_ref"),
                                                                "aliases": o.get("aliases", [])[:20] if isinstance(o.get("aliases"), list) else []},
                                      observed_at=_dt(o.get("created")), confidence="low"))
        elif t == "indicator":
            iocs = extract_pattern_iocs(str(o.get("pattern", "")))
            for k, v in iocs:
                add(k, v)
                by_id.setdefault(o["id"], (k, v))
            p.observations.append(Obs("CYBINT", "cti.indicator", {
                "id": o["id"], "name": str(o.get("name", ""))[:200], "pattern": str(o.get("pattern", ""))[:2000],
                "pattern_type": o.get("pattern_type"), "valid_from": o.get("valid_from"), "valid_until": o.get("valid_until"),
                "producer_confidence": o.get("confidence"), "producer": o.get("created_by_ref"),
                "iocs": [{"type": k, "value": v} for k, v in iocs],
                "note": "reported by the bundle producer; not independently verified"},
                observed_at=_dt(o.get("valid_from") or o.get("created")), confidence="low"))
        elif t in _IOC_TYPE and isinstance(o.get("value"), str):
            k = _IOC_TYPE[t]
            v = o["value"].lower() if t == "domain-name" else o["value"]
            add(k, v)
            by_id[o["id"]] = (k, v)
    for o in objs:
        if isinstance(o, dict) and o.get("type") == "relationship":
            a, b = by_id.get(str(o.get("source_ref"))), by_id.get(str(o.get("target_ref")))
            if a and b and a != b:
                p.relationships.append(RelDraft(a, b, str(o.get("relationship_type", "related-to"))[:60].replace("-", "_"),
                                                f"asserted by the STIX producer ({o.get('created_by_ref') or 'unknown'}); "
                                                "attribution is not verified"))
    if skipped:
        p.warnings.append(f"{skipped} object(s) skipped: missing or malformed STIX id/type.")
    p.summary = {"objects": len(objs), "by_type": dict(counts), "skipped": skipped, "entities": len(p.entities)}
    if not p.observations and not p.entities:
        raise IngestError("bundle contains no usable indicators, observables or threat objects")
    return p


def _dt(s):
    if not s or not isinstance(s, str):
        return None
    try:
        d = datetime.fromisoformat(s.replace("Z", "+00:00"))
        return d if d.tzinfo else d.replace(tzinfo=UTC)
    except ValueError:
        return None


_NS = uuid.UUID("0b1f6f5e-0f4c-4a6e-9b4e-6f0a0c1c0a11")  # fixed namespace => deterministic, repeatable export ids


def stix_id(kind: str, value: str) -> str:
    return f"{kind}--{uuid.uuid5(_NS, f'{kind}:{value}')}"


def export_stix(entities: list[dict[str, Any]], relationships: list[dict[str, Any]], created: str) -> dict[str, Any]:
    """Domains/IPs/URLs as STIX Cyber Observables, malware/threat-actor/campaign/tool/intrusion-set as SDOs, and the
    relationships between them. Confidence stays a label (x_osintcc_*); nothing is upgraded to 'attribution'."""
    sco = {"domain": "domain-name", "ip": "ipv4-addr", "url": "url"}
    sdo = {"malware": "malware", "threat_actor": "threat-actor", "campaign": "campaign", "tool": "tool",
           "intrusion_set": "intrusion-set"}
    sdo_rels = {"uses", "targets", "attributed-to", "indicates", "variant-of", "related-to"}
    ident = stix_id("identity", "osintcc")
    objs: list[dict[str, Any]] = [{
        "type": "identity", "spec_version": "2.1", "id": ident, "created": created,
        "modified": created, "name": "OSINT Command Center export", "identity_class": "system"}]
    ids: dict[str, tuple[str, str]] = {}
    for e in entities:
        if e["type"] in sco:
            t = "ipv6-addr" if e["type"] == "ip" and ":" in e["key"] else sco[e["type"]]
            sid = stix_id(t, e["key"])
            ids[e["id"]] = (sid, "sco")
            objs.append({"type": t, "spec_version": "2.1", "id": sid, "value": e["key"],
                         "x_osintcc_note": "observed by a public source; not verified"})
        elif e["type"] in sdo:
            t = sdo[e["type"]]
            sid = stix_id(t, e["key"])
            ids[e["id"]] = (sid, "sdo")
            objs.append({"type": t, "spec_version": "2.1", "id": sid, "created": created, "modified": created,
                         "name": e["key"], "created_by_ref": ident,
                         "x_osintcc_note": "reported by an imported source; not verified"})
    rel_map = {"resolves_to": "resolves-to", "uses": "uses", "attributed_to": "attributed-to", "targets": "targets"}
    for r in relationships:
        a, b = ids.get(r["from"]), ids.get(r["to"])
        if not (a and b):
            continue
        rt = rel_map.get(r["type"], "related-to")
        if (a[1] == "sco" or b[1] == "sco") and rt not in ("resolves-to", "related-to"):
            rt = "related-to"  # STIX restricts which object classes may use the stricter relationship types
        if rt not in sdo_rels and rt != "resolves-to":
            rt = "related-to"
        objs.append({"type": "relationship", "spec_version": "2.1",
                     "id": stix_id("relationship", f"{a[0]}|{r['type']}|{b[0]}"), "created": created, "modified": created,
                     "relationship_type": rt, "source_ref": a[0], "target_ref": b[0], "created_by_ref": ident,
                     "x_osintcc_status": r["status"], "x_osintcc_confidence": r["confidence"],
                     "x_osintcc_evidence_ids": r["evidence_ids"]})
    return {"type": "bundle", "id": stix_id("bundle", created), "objects": objs}


def _detect(name: str, head: bytes) -> str | None:
    if head[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x0a\x0d\x0d\x0a"):
        return "pcap"
    if name.endswith((".stix", ".stix.json", ".stix2")) or (name.endswith(".json") and b'"bundle"' in head):
        return "stix"
    return None


PARSERS["pcap"] = parse_pcap
PARSERS["stix"] = parse_stix
DETECTORS.append(_detect)
