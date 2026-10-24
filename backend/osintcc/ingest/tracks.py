"""Public-broadcast and GPS track importers: ADS-B (readsb/dump1090 JSON), AIS (NMEA !AIVDM), GPS NMEA (GGA/RMC).

Import-only. These describe aircraft, vessels or an owned GPS receiver; they are NOT a module for following people and
there is no live feed. Identifiers (ICAO hex, MMSI) name transponders, which may be registered to individuals: they are
stored as entities with a note and never resolved to owners.
"""
from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from typing import Any

from .parsers import DETECTORS, PARSERS, EntityDraft, IngestError, Obs, ParsedIngest

MAX_TRACKS = 5000
LICENCE_NOTE = ("Public broadcast data (ADS-B/AIS). Check the source's redistribution licence before sharing; "
                "exact positions of private aircraft/vessels can be sensitive.")


def parse_adsb(data: bytes) -> ParsedIngest:
    try:
        d = json.loads(data)
    except ValueError as exc:
        raise IngestError("not valid JSON") from exc
    ac = d.get("aircraft") if isinstance(d, dict) else None
    if not isinstance(ac, list):
        raise IngestError("not an aircraft.json document (needs an 'aircraft' list)")
    if len(ac) > MAX_TRACKS:
        raise IngestError(f"more than {MAX_TRACKS} aircraft records")
    now = d.get("now")
    when = datetime.fromtimestamp(float(now), UTC) if isinstance(now, (int, float)) else None
    p = ParsedIngest("adsb", "OSINT", {"aircraft": 0}, mime="application/json", access_class="PUBLIC")
    n = 0
    for a in ac:
        if not isinstance(a, dict) or not re.fullmatch(r"~?[0-9a-fA-F]{6}", str(a.get("hex", ""))):
            continue
        lat, lon = a.get("lat"), a.get("lon")
        if not (isinstance(lat, (int, float)) and isinstance(lon, (int, float)) and abs(lat) <= 90 and abs(lon) <= 180):
            lat = lon = None
        hexid = str(a["hex"]).lower().lstrip("~")
        p.entities.append(EntityDraft("aircraft", f"icao:{hexid}", f"{(a.get('flight') or '').strip() or 'aircraft'} (icao {hexid})"))
        p.observations.append(Obs("OSINT", "track.adsb_aircraft", {
            "icao_hex": hexid, "callsign": (a.get("flight") or "").strip() or None, "altitude_ft_baro": a.get("alt_baro"),
            "ground_speed_kt": a.get("gs"), "track_deg": a.get("track"),
            "location": ({"lat": lat, "lon": lon, "crs": "EPSG:4326", "accuracy_m": None,
                          "accuracy_note": "ADS-B reports position integrity classes, not metres; accuracy unknown here"}
                         if lat is not None else None),
            "seconds_since_position": a.get("seen_pos"), "licence": LICENCE_NOTE, "mlat": bool(a.get("mlat"))},
            observed_at=when, confidence="medium"))
        n += 1
    if not n:
        raise IngestError("no valid aircraft records")
    p.summary["aircraft"] = n
    p.warnings.append("Transponder identifiers are not resolved to owners; positions are a point-in-time snapshot.")
    return p


_SIX = {c: i for i, c in enumerate("0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVW`abcdefghijklmnopqrstuvw")}


def _nmea_ok(line: str) -> bool:
    if "*" not in line or not line[0] in "!$":
        return False
    body, _, cs = line[1:].partition("*")
    x = 0
    for ch in body:
        x ^= ord(ch)
    return len(cs.strip()) >= 2 and cs.strip()[:2].upper() == f"{x:02X}"


def _bits(payload: str) -> str:
    out = []
    for c in payload:
        v = ord(c) - 48
        v = v - 8 if v > 40 else v
        if not 0 <= v < 64:
            raise IngestError("invalid AIS payload character")
        out.append(f"{v:06b}")
    return "".join(out)


def _s(b: str, a: int, n: int, signed: bool = False) -> int:
    v = int(b[a:a + n], 2)
    return v - (1 << n) if signed and v >= 1 << (n - 1) else v


def parse_ais(data: bytes) -> ParsedIngest:
    lines = [ln.strip() for ln in data.decode("ascii", "replace").splitlines() if ln.startswith(("!AIVDM", "!AIVDO"))]
    if not lines:
        raise IngestError("no !AIVDM sentences found")
    if len(lines) > 50_000:
        raise IngestError("too many sentences; split the file")
    p = ParsedIngest("ais", "OSINT", {}, mime="text/plain", access_class="PUBLIC")
    bad = 0
    seen: dict[int, dict[str, Any]] = {}
    for ln in lines:
        if not _nmea_ok(ln):
            bad += 1
            continue
        f = ln[1:].split("*")[0].split(",")
        if len(f) < 7 or f[1] != "1":  # multi-sentence messages are skipped (position reports are single-sentence)
            continue
        try:
            b = _bits(f[5])
            mt = _s(b, 0, 6)
            if mt not in (1, 2, 3) or len(b) < 168:
                continue
            mmsi = _s(b, 8, 30)
            lon, lat = _s(b, 61, 28, True) / 600000.0, _s(b, 89, 27, True) / 600000.0
            sog = _s(b, 50, 10) / 10.0
        except (IngestError, ValueError):
            bad += 1
            continue
        if abs(lat) > 90 or abs(lon) > 180:
            continue  # 91/181 mean "not available"
        seen[mmsi] = {"mmsi": mmsi, "location": {"lat": round(lat, 6), "lon": round(lon, 6), "crs": "EPSG:4326", "accuracy_m": None,
                                                  "accuracy_note": "AIS position accuracy flag not interpreted; unknown"},
                      "sog_kt": sog, "message_type": mt, "licence": LICENCE_NOTE}
    if not seen:
        raise IngestError("no valid position reports (checksums failed or unsupported message types)")
    for m, o in seen.items():
        p.entities.append(EntityDraft("vessel", f"mmsi:{m}", f"vessel mmsi {m}"))
        p.observations.append(Obs("OSINT", "track.ais_vessel", o, confidence="medium"))
    p.summary.update(vessels=len(seen), checksum_failures=bad)
    if bad:
        p.warnings.append(f"{bad} sentence(s) failed the NMEA checksum or were malformed and were ignored.")
    p.warnings.append("AIS has no capture timestamp in the position message; observed_at is unknown.")
    return p


def _deg(v: str, hemi: str) -> float | None:
    if not v or "." not in v:
        return None
    dot = v.index(".")
    d, m = float(v[:dot - 2] or 0), float(v[dot - 2:])
    r = d + m / 60
    return -r if hemi in ("S", "W") else r


def parse_nmea_gps(data: bytes) -> ParsedIngest:
    pts: list[dict[str, Any]] = []
    bad = 0
    for ln in data.decode("ascii", "replace").splitlines():
        ln = ln.strip()
        if not ln.startswith("$") or ln[3:6] not in ("GGA", "RMC"):
            continue
        if not _nmea_ok(ln):
            bad += 1
            continue
        f = ln[1:].split("*")[0].split(",")
        try:
            if f[0][2:] == "GGA" and len(f) > 9 and f[6] not in ("", "0"):
                lat, lon = _deg(f[2], f[3]), _deg(f[4], f[5])
                hdop = float(f[8]) if f[8] else None
                pts.append({"time_utc_hhmmss": f[1].split(".")[0], "lat": lat, "lon": lon, "hdop": hdop, "satellites": int(f[7] or 0),
                            "altitude_m": float(f[9]) if f[9] else None, "source": "GGA"})
            elif f[0][2:] == "RMC" and len(f) > 9 and f[2] == "A":
                lat, lon = _deg(f[3], f[4]), _deg(f[5], f[6])
                pts.append({"time_utc_hhmmss": f[1].split(".")[0], "date_ddmmyy": f[9], "lat": lat, "lon": lon, "speed_kt": float(f[7] or 0), "source": "RMC"})
        except (ValueError, IndexError):
            bad += 1
    pts = [x for x in pts if isinstance(x["lat"], float) and isinstance(x["lon"], float) and abs(x["lat"]) <= 90
           and abs(x["lon"]) <= 180][:MAX_TRACKS]
    if not pts:
        raise IngestError("no valid GGA/RMC fixes (checksums must match)")
    p = ParsedIngest("gps_nmea", "GEOINT", {"fixes": len(pts), "checksum_failures": bad}, mime="text/plain", access_class="OWNED_AUTHORIZED",
                     sensitivity="RESTRICTED")
    first, last = pts[0], pts[-1]
    p.observations.append(Obs("GEOINT", "geo.gps_track", {
        "fixes": len(pts), "first": first, "last": last, "points": pts[:500],
        "location": {"lat": round(last["lat"], 6), "lon": round(last["lon"], 6), "crs": "EPSG:4326", "accuracy_m": None,
                     "accuracy_note": "HDOP is a dilution factor, not metres; accuracy unknown"},
        "provenance": "owner-supplied GPS receiver log"}, confidence="medium", sensitivity="RESTRICTED"))
    if bad:
        p.warnings.append(f"{bad} sentence(s) failed validation and were ignored.")
    p.warnings.append("A GPS log can reveal a person's movements: stored RESTRICTED and excluded from default exports.")
    return p


def _detect(name: str, head: bytes) -> str | None:
    if name.endswith((".aircraft.json", "aircraft.json")) or (name.endswith(".json") and b'"aircraft"' in head):
        return "adsb"
    if head.startswith(b"!AIVD") or name.endswith(".ais"):
        return "ais"
    if name.endswith((".nmea", ".gps")) or head.startswith((b"$GPGGA", b"$GPRMC", b"$GNGGA", b"$GNRMC")):
        return "gps_nmea"
    return None


PARSERS["adsb"] = parse_adsb
PARSERS["ais"] = parse_ais
PARSERS["gps_nmea"] = parse_nmea_gps
DETECTORS.insert(0, _detect)
