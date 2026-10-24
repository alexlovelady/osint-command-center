"""FISINT / ELINT importers (spec 21.1, 21.7 P4B): CCSDS space packets, calibrated telemetry CSV, synthetic pulse trains.

Scope guards: telemetry is only what the analyst supplies (public test data, owned systems); pulse-train files must
declare `# provenance: synthetic` or `# provenance: owned_lab` or they are rejected. No emitter identification, no
geolocation, no library matching, nothing is transmitted or decoded from restricted sources.
"""
from __future__ import annotations

import csv
import io
import re
import struct
from collections import defaultdict
from datetime import UTC, datetime
from typing import Any

import numpy as np

from .parsers import DETECTORS, PARSERS, IngestError, Obs, ParsedIngest

MAX_PACKETS = 1_000_000


def parse_ccsds(data: bytes) -> ParsedIngest:
    pos, n = 0, 0
    apids: dict[int, dict[str, Any]] = {}
    while pos < len(data):
        if pos + 6 > len(data):
            raise IngestError(f"truncated packet header at byte {pos}")
        w0, w1, ln = struct.unpack(">HHH", data[pos:pos + 6])
        if w0 >> 13 != 0:
            raise IngestError(f"unsupported CCSDS packet version at byte {pos} (not a space-packet stream)")
        apid, seq, size = w0 & 0x7FF, w1 & 0x3FFF, ln + 1
        if pos + 6 + size > len(data):
            raise IngestError(f"packet at byte {pos} overruns the file")
        a = apids.setdefault(apid, {"packets": 0, "bytes": 0, "gaps": 0, "dup_or_reorder": 0, "last_seq": None,
                                    "type": "telecommand" if (w0 >> 12) & 1 else "telemetry",
                                    "secondary_header": bool((w0 >> 11) & 1), "min_len": size, "max_len": size})
        if a["last_seq"] is not None:
            step = (seq - a["last_seq"]) % 16384
            if step == 0:
                a["dup_or_reorder"] += 1
            elif step != 1:
                a["gaps"] += step - 1
        a.update(last_seq=seq, packets=a["packets"] + 1, bytes=a["bytes"] + size, min_len=min(a["min_len"], size),
                 max_len=max(a["max_len"], size))
        pos += 6 + size
        n += 1
        if n > MAX_PACKETS:
            raise IngestError(f"more than {MAX_PACKETS} packets; split the file")
    if n == 0:
        raise IngestError("empty file")
    for a in apids.values():
        a.pop("last_seq")
    info = {"packets": n, "apids": {str(k): v for k, v in sorted(apids.items())},
            "decoding": "primary headers only; payload fields are not interpreted without a mission dictionary",
            "provenance": "analyst-supplied packet stream; no uplink, no live reception, no decryption"}
    p = ParsedIngest("ccsds", "FISINT", {"packets": n, "apids": len(apids)}, mime="application/octet-stream",
                     access_class="IMPORTED")
    p.observations.append(Obs("FISINT", "telemetry.ccsds_summary", info, confidence="medium"))
    if any(a["gaps"] for a in apids.values()):
        p.warnings.append("Sequence-count gaps found: packets may be missing from the capture (cause unknown).")
    return p


def parse_telemetry_csv(data: bytes) -> ParsedIngest:
    """timestamp,parameter,raw[,unit,slope,offset]. Engineering values are computed only when calibration is supplied."""
    rd = csv.DictReader(io.StringIO(data.decode("utf-8-sig", "replace")))
    need = {"timestamp", "parameter", "raw"}
    if not rd.fieldnames or not need <= {f.strip().lower() for f in rd.fieldnames}:
        raise IngestError("CSV needs timestamp, parameter and raw columns")
    cols = {f.strip().lower(): f for f in rd.fieldnames}
    series: dict[str, list[tuple[datetime, float]]] = defaultdict(list)
    cal: dict[str, tuple[float, float, str]] = {}
    for i, row in enumerate(rd):
        if i >= 500_000:
            raise IngestError("more than 500000 rows; split the file")
        try:
            t = datetime.fromisoformat(row[cols["timestamp"]].strip().replace("Z", "+00:00"))
            t = t if t.tzinfo else t.replace(tzinfo=UTC)
            raw = float(row[cols["raw"]])
        except (ValueError, TypeError, AttributeError) as exc:
            raise IngestError(f"row {i + 2}: invalid timestamp or raw value") from exc
        name = row[cols["parameter"]].strip()[:80]
        if not name:
            raise IngestError(f"row {i + 2}: empty parameter name")
        series[name].append((t, raw))
        if "slope" in cols and row.get(cols["slope"]) not in (None, ""):
            try:
                cal[name] = (float(row[cols["slope"]]), float(row.get(cols.get("offset", ""), 0) or 0),
                             (row.get(cols.get("unit", ""), "") or "").strip())
            except ValueError as exc:
                raise IngestError(f"row {i + 2}: invalid calibration") from exc
    if not series:
        raise IngestError("no telemetry rows")
    params = {}
    for name, pts in series.items():
        raws = np.array([v for _, v in pts])
        d: dict[str, Any] = {"n": len(pts), "start": min(t for t, _ in pts).isoformat(), "end": max(t for t, _ in pts).isoformat(),
                             "raw_min": float(raws.min()), "raw_max": float(raws.max())}
        if name in cal:
            s, o, u = cal[name]
            eng = raws * s + o
            d.update(calibrated=True, unit=u or "unspecified", slope=s, offset=o, eng_min=float(eng.min()),
                     eng_max=float(eng.max()), eng_mean=float(eng.mean()))
        else:
            d.update(calibrated=False, unit="raw counts (no calibration supplied)")
        params[name] = d
    p = ParsedIngest("telemetry_csv", "FISINT", {"parameters": len(params), "rows": sum(len(v) for v in series.values())},
                     mime="text/csv", access_class="OWNED_AUTHORIZED")
    p.observations.append(Obs("FISINT", "telemetry.parameter_summary", {"parameters": params}, confidence="medium",
                              observed_at=min(t for pts in series.values() for t, _ in pts)))
    if not cal:
        p.warnings.append("No calibration columns: values are raw counts, not engineering units.")
    return p


_PROV = re.compile(r"^#\s*provenance\s*:\s*(\w+)", re.IGNORECASE | re.MULTILINE)


def parse_pulses(data: bytes) -> ParsedIngest:
    text = data.decode("utf-8-sig", "replace")
    m = _PROV.search(text)
    if not m or m.group(1).lower() not in ("synthetic", "owned_lab"):
        raise IngestError("pulse files must declare '# provenance: synthetic' or '# provenance: owned_lab'; "
                          "recordings of third-party emitters are not accepted")
    prov = m.group(1).lower()
    body = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    rd = csv.DictReader(io.StringIO(body))
    if not rd.fieldnames or not {"toa_us", "pw_us", "freq_mhz"} <= {f.strip().lower() for f in rd.fieldnames}:
        raise IngestError("CSV needs toa_us, pw_us and freq_mhz columns (amp_db optional)")
    cols = {f.strip().lower(): f for f in rd.fieldnames}
    toa, pw, fr, amp = [], [], [], []
    for i, row in enumerate(rd):
        if i >= 200_000:
            raise IngestError("more than 200000 pulses")
        try:
            toa.append(float(row[cols["toa_us"]]))
            pw.append(float(row[cols["pw_us"]]))
            fr.append(float(row[cols["freq_mhz"]]))
            if "amp_db" in cols and row.get(cols["amp_db"]):
                amp.append(float(row[cols["amp_db"]]))
        except (ValueError, TypeError) as exc:
            raise IngestError(f"row {i + 2}: non-numeric value") from exc
    if len(toa) < 8:
        raise IngestError("need at least 8 pulses")
    t = np.array(toa)
    if np.any(np.diff(t) <= 0):
        raise IngestError("toa_us must be strictly increasing")
    pri = np.diff(t)
    med = float(np.median(pri))
    jitter = float(np.std(pri) / med * 100) if med else float("nan")
    _, counts = np.unique(np.round(pri / med / 0.02) * 0.02, return_counts=True)
    major = int(np.sum(counts >= max(3, 0.1 * len(pri))))  # PRI levels that each carry >=10% of intervals
    if jitter < 1.0:
        pattern = "stable"
    elif 2 <= major <= 6 and int(counts[counts >= max(3, 0.1 * len(pri))].sum()) >= 0.9 * len(pri):
        pattern = "staggered/multi-level"
    elif jitter < 10:
        pattern = "jittered"
    else:
        pattern = "irregular"
    stats = {"pulses": len(t), "pri_us_median": med, "pri_jitter_percent": round(jitter, 2), "pri_pattern": pattern,
             "pw_us_median": float(np.median(pw)), "freq_mhz_median": float(np.median(fr)),
             "freq_mhz_min": float(min(fr)), "freq_mhz_max": float(max(fr)),
             "amp_db_median": float(np.median(amp)) if amp else None, "provenance": prov,
             "identification": "none: descriptor statistics only; no emitter identification, library match or geolocation"}
    p = ParsedIngest("pulses", "ELINT", {"pulses": len(t), "pri_us": med, "pattern": pattern}, mime="text/csv",
                     access_class="SIMULATION" if prov == "synthetic" else "OWNED_AUTHORIZED")
    p.observations.append(Obs("ELINT", "emitter.pulse_train_stats", stats, confidence="low"))
    p.warnings.append(f"Educational analysis of {prov} data only.")
    return p


def _detect(name: str, head: bytes) -> str | None:
    if name.endswith((".ccsds", ".spp")):
        return "ccsds"
    if name.endswith(".pulses.csv") or b"toa_us" in head[:400]:
        return "pulses"
    if name.endswith((".tlm.csv", ".telemetry.csv")) or (name.endswith(".csv") and head.lower().startswith(b"timestamp,parameter")):
        return "telemetry_csv"
    return None


PARSERS["ccsds"] = parse_ccsds
PARSERS["telemetry_csv"] = parse_telemetry_csv
PARSERS["pulses"] = parse_pulses
DETECTORS.insert(0, _detect)  # before the generic *.csv sensor rule
