"""Offline, import-only parsers (spec §21). Pure functions: bytes in, a ParsedIngest out.

Nothing here touches the network, executes embedded content, or contacts a provider. Malformed input raises
IngestError *before* anything is stored, so a bad file cannot alter evidence.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import re
import tarfile
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses, parsedate_to_datetime
from typing import Any

import nh3
import numpy as np

PARSER_VERSION = "1.0.0"
MAX_SAMPLES_ANALYSED = 1 << 22
MAX_SENSOR_ROWS = 200_000
MAX_SIGMF_DATA = 512 * 1024 * 1024


class IngestError(ValueError):
    pass


@dataclass
class Obs:
    discipline: str
    kind: str
    data: dict[str, Any]
    observed_at: datetime | None = None
    confidence: str = "unknown"
    sensitivity: str = "INTERNAL"


@dataclass
class EntityDraft:
    type: str
    key: str
    display: str


@dataclass
class RelDraft:
    from_key: tuple[str, str]
    to_key: tuple[str, str]
    relation_type: str
    reason: str


@dataclass
class ParsedIngest:
    kind: str
    discipline: str
    summary: dict[str, Any]
    observations: list[Obs] = field(default_factory=list)
    entities: list[EntityDraft] = field(default_factory=list)
    relationships: list[RelDraft] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    sensitivity: str = "INTERNAL"
    access_class: str = "IMPORTED"  # PUBLIC | OWNED_AUTHORIZED | CONSENTED | IMPORTED | SIMULATION
    mime: str = "application/octet-stream"
    layers: list[dict[str, Any]] = field(default_factory=list)  # geospatial_layers rows to create


# ------------------------------------------------------------------ COMINT: user-supplied EML ---------------------
_EMAIL_RE = re.compile(r"^[^@\s<>]{1,64}@[A-Za-z0-9.-]{1,253}$")


def parse_eml(data: bytes) -> ParsedIngest:
    """Headers are *claims made by the message*, never verified facts. HTML is reduced to inert text; attachments are
    only catalogued (hash/size/type) and are never extracted, opened or executed."""
    if not data.strip():
        raise IngestError("empty message")
    msg = BytesParser(policy=policy.default).parsebytes(data)
    if not any(msg.get(h) for h in ("From", "To", "Subject", "Date", "Message-ID")):
        raise IngestError("not an RFC 5322 message (no recognizable headers)")

    def addrs(h: str) -> list[str]:
        out = []
        for _, a in getaddresses([str(v) for v in msg.get_all(h, [])]):
            a = a.strip()
            if _EMAIL_RE.match(a):
                out.append(a.split("@")[0] + "@" + a.split("@")[1].lower())
        return out

    sent_at = None
    warnings: list[str] = []
    if msg.get("Date"):
        try:
            sent_at = parsedate_to_datetime(str(msg["Date"]))
            if sent_at.tzinfo is None:
                sent_at = sent_at.replace(tzinfo=UTC)
                warnings.append("Date header has no timezone; UTC assumed.")
        except (TypeError, ValueError):
            warnings.append("Date header unparseable; time is unknown.")
    body_part = msg.get_body(preferencelist=("plain", "html"))
    body = ""
    if body_part is not None:
        raw = body_part.get_content()
        body = nh3.clean(raw, tags=set()) if body_part.get_content_type() == "text/html" else raw
    attachments = []
    for part in msg.iter_attachments():
        payload = bytes(part.get_payload(decode=True) or b"")
        attachments.append({"filename": part.get_filename() or "(unnamed)", "content_type": part.get_content_type(),
                            "bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest(),
                            "status": "quarantined (not opened or extracted)"})
    sender, to, cc = addrs("From"), addrs("To"), addrs("Cc")
    claims = {"claimed_from": sender, "claimed_to": to, "claimed_cc": cc,
              "claimed_subject": str(msg.get("Subject", "")), "claimed_message_id": str(msg.get("Message-ID", "")),
              "claimed_sent_at": sent_at.isoformat() if sent_at else None,
              "body_text_excerpt": body.strip()[:2000], "attachments": attachments,
              "received_hops": len(msg.get_all("Received", [])),
              "authenticity": "unverified: headers can be forged; no DKIM/SPF validation performed"}
    p = ParsedIngest("eml", "COMINT", {"from": sender, "recipients": len(to) + len(cc),
                                       "attachments": len(attachments)}, warnings=warnings, sensitivity="RESTRICTED",
                     mime="message/rfc822")
    p.observations.append(Obs("COMINT", "email.message", claims, observed_at=sent_at, confidence="unknown",
                              sensitivity="RESTRICTED"))
    seen = set()
    for a in sender + to + cc:
        if a not in seen:
            seen.add(a)
            p.entities.append(EntityDraft("email", a, a))
    for s in sender[:1]:
        for r in to + cc:
            p.relationships.append(RelDraft(("email", s), ("email", r), "claimed_correspondent",
                                            "The message header claims this sender/recipient pair; unverified"))
    if not sender:
        p.warnings.append("No valid From address found.")
    return p


# ------------------------------------------------------------------ SIGINT: SigMF IQ + FFT ------------------------
_DTYPES: dict[str, tuple[np.dtype, int]] = {"cf32_le": (np.dtype("<f4"), 2), "ci16_le": (np.dtype("<i2"), 2), "ci8": (np.dtype("i1"), 2),
           "cu8": (np.dtype("u1"), 2), "rf32_le": (np.dtype("<f4"), 1), "ri16_le": (np.dtype("<i2"), 1)}


def _read_sigmf_archive(data: bytes) -> tuple[dict, bytes]:
    try:
        tf = tarfile.open(fileobj=io.BytesIO(data), mode="r:")
    except tarfile.TarError as exc:
        raise IngestError("not a SigMF archive (tar)") from exc
    meta_b = data_b = None
    with tf:
        members = tf.getmembers()
        if len(members) > 8:
            raise IngestError("unexpected number of archive members")
        for m in members:
            if not m.isfile() or m.name.startswith(("/", "..")) or ".." in m.name.split("/"):
                raise IngestError(f"unsafe archive member: {m.name!r}")
            if m.name.endswith(".sigmf-meta"):
                if m.size > 2 * 1024 * 1024:
                    raise IngestError("metadata too large")
                fh = tf.extractfile(m)
                meta_b = fh.read() if fh else None
            elif m.name.endswith(".sigmf-data"):
                if m.size > MAX_SIGMF_DATA:
                    raise IngestError("sample data exceeds size limit")
                fh = tf.extractfile(m)
                data_b = fh.read() if fh else None
    if meta_b is None or data_b is None:
        raise IngestError("archive must contain one .sigmf-meta and one .sigmf-data")
    try:
        meta = json.loads(meta_b)
    except ValueError as exc:
        raise IngestError("SigMF metadata is not valid JSON") from exc
    return meta, data_b


def validate_sigmf_meta(meta: dict) -> dict:
    g = meta.get("global") if isinstance(meta, dict) else None
    if not isinstance(g, dict):
        raise IngestError("SigMF metadata missing 'global'")
    dtype = g.get("core:datatype")
    if dtype not in _DTYPES:
        raise IngestError(f"unsupported or missing core:datatype: {dtype!r}")
    sr = g.get("core:sample_rate")
    if not isinstance(sr, (int, float)) or isinstance(sr, bool) or not (0 < sr < 1e12):
        raise IngestError("core:sample_rate missing or invalid")
    if not isinstance(g.get("core:version"), str):
        raise IngestError("core:version missing")
    if not isinstance(meta.get("captures", []), list) or not isinstance(meta.get("annotations", []), list):
        raise IngestError("captures/annotations must be lists")
    return g


def decode_iq(raw: bytes, dtype_name: str, limit: int = MAX_SAMPLES_ANALYSED) -> np.ndarray:
    dt, comps = _DTYPES[dtype_name]
    n = min(len(raw) // (dt.itemsize * comps), limit)
    if n == 0:
        raise IngestError("no samples in data file")
    arr = np.frombuffer(raw, dtype=dt, count=n * comps).astype(np.float32)
    if dtype_name == "cu8":
        arr = arr - 127.5
    if comps == 2:
        return arr[0::2] + 1j * arr[1::2]
    return arr.astype(np.complex64)


def spectral_peaks(iq: np.ndarray, sample_rate: float, nfft: int = 4096, max_peaks: int = 5,
                   min_snr_db: float = 15.0) -> dict[str, Any]:
    """Welch-style averaged periodogram (Hann window, 50% overlap, bounded). Peaks reported as offset from centre."""
    if nfft & (nfft - 1) or not 64 <= nfft <= 1 << 16:
        raise IngestError("nfft must be a power of two between 64 and 65536")
    if len(iq) < nfft:
        raise IngestError(f"need at least {nfft} samples, got {len(iq)}")
    win = np.hanning(nfft).astype(np.float32)
    step = nfft // 2
    nseg = min((len(iq) - nfft) // step + 1, 512)
    acc = np.zeros(nfft, dtype=np.float64)
    for i in range(nseg):
        seg = iq[i * step:i * step + nfft] * win
        acc += np.abs(np.fft.fft(seg)) ** 2
    psd = np.fft.fftshift(acc / nseg)
    freqs = np.fft.fftshift(np.fft.fftfreq(nfft, d=1.0 / sample_rate))
    db = 10 * np.log10(psd + 1e-20)
    floor = float(np.median(db))
    peaks = []
    work = db.copy()
    for _ in range(max_peaks):
        k = int(np.argmax(work))
        snr = float(work[k] - floor)
        if snr < min_snr_db:
            break
        peaks.append({"offset_hz": float(freqs[k]), "snr_db": round(snr, 1), "power_db": round(float(work[k]), 1)})
        work[max(0, k - 3):k + 4] = -400  # suppress the main lobe before looking for the next peak
    return {"nfft": nfft, "bin_width_hz": sample_rate / nfft, "segments": nseg, "noise_floor_db": round(floor, 1),
            "peaks": peaks}


def parse_sigmf(data: bytes) -> ParsedIngest:
    meta, raw = _read_sigmf_archive(data)
    g = validate_sigmf_meta(meta)
    iq = decode_iq(raw, g["core:datatype"])
    sr = float(g["core:sample_rate"])
    caps = meta.get("captures") or [{}]
    centre = float(caps[0].get("core:frequency", 0.0) or 0.0)
    start = None
    if caps[0].get("core:datetime"):
        try:
            start = datetime.fromisoformat(str(caps[0]["core:datetime"]).replace("Z", "+00:00"))
            if start.tzinfo is None:
                start = start.replace(tzinfo=UTC)
        except ValueError:
            start = None
    spec = spectral_peaks(iq, sr)
    for p in spec["peaks"]:
        p["absolute_hz"] = centre + p["offset_hz"]
    info = {"datatype": g["core:datatype"], "sample_rate_hz": sr, "centre_frequency_hz": centre,
            "samples_analysed": len(iq), "samples_in_file_bytes": len(raw), "sigmf_version": g["core:version"],
            "description": str(g.get("core:description", ""))[:500], "spectrum": spec,
            "provenance": "user-supplied recording; transmitter identity and location are NOT inferred"}
    p = ParsedIngest("sigmf", "SIGINT", {"peaks": len(spec["peaks"]), "sample_rate_hz": sr, "centre_hz": centre},
                     mime="application/x-tar")
    p.observations.append(Obs("SIGINT", "rf.spectral_peaks", info, observed_at=start,
                              confidence="medium" if spec["peaks"] else "low"))
    if not spec["peaks"]:
        p.warnings.append("No narrowband peak above the noise floor; this does not mean no signal was present.")
    if start is None:
        p.warnings.append("Capture time missing from metadata; observed_at is unknown.")
    if centre == 0.0:
        p.warnings.append("core:frequency missing; absolute frequencies equal baseband offsets.")
    return p


# ------------------------------------------------------------------ MASINT: owned sensor series -------------------
def parse_sensor_csv(data: bytes, z_threshold: float = 6.0) -> ParsedIngest:
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise IngestError("CSV must be UTF-8") from exc
    rd = csv.DictReader(io.StringIO(text))
    if not rd.fieldnames or not {"timestamp", "value"} <= {f.strip().lower() for f in rd.fieldnames}:
        raise IngestError("CSV needs 'timestamp' and 'value' columns")
    cols = {f.strip().lower(): f for f in rd.fieldnames}
    ts, vals, unit, sensor, assumed_utc = [], [], "", "", False
    for i, row in enumerate(rd):
        if i >= MAX_SENSOR_ROWS:
            raise IngestError(f"more than {MAX_SENSOR_ROWS} rows; split the file")
        try:
            t = datetime.fromisoformat(row[cols["timestamp"]].strip().replace("Z", "+00:00"))
            v = float(row[cols["value"]])
        except (ValueError, TypeError, AttributeError) as exc:
            raise IngestError(f"row {i + 2}: invalid timestamp or value") from exc
        if not np.isfinite(v):
            raise IngestError(f"row {i + 2}: non-finite value")
        if t.tzinfo is None:
            t, assumed_utc = t.replace(tzinfo=UTC), True
        ts.append(t)
        vals.append(v)
        unit = unit or (row.get(cols.get("unit", ""), "") or "").strip()
        sensor = sensor or (row.get(cols.get("sensor", ""), "") or "").strip()
    if len(vals) < 10:
        raise IngestError("need at least 10 samples")
    order = np.argsort([t.timestamp() for t in ts])
    ts = [ts[i] for i in order]
    x = np.asarray(vals, dtype=np.float64)[order]
    med = float(np.median(x))
    mad = float(np.median(np.abs(x - med))) or 1e-12
    z = 0.6745 * (x - med) / mad
    flagged = np.abs(z) > z_threshold
    dts = np.diff([t.timestamp() for t in ts])
    gap = 3 * float(np.median(dts)) if len(dts) else 0.0
    intervals: list[dict[str, Any]] = []
    for i in map(int, np.flatnonzero(flagged)):
        if intervals and (ts[i].timestamp() - intervals[-1]["_last"]) <= gap:
            iv = intervals[-1]
            iv["end"], iv["_last"], iv["points"] = ts[i].isoformat(), ts[i].timestamp(), iv["points"] + 1
            if abs(z[i]) > abs(iv["peak_z"]):
                iv["peak_z"], iv["peak_value"] = round(float(z[i]), 2), float(x[i])
        else:
            intervals.append({"start": ts[i].isoformat(), "end": ts[i].isoformat(), "_last": ts[i].timestamp(),
                              "points": 1, "peak_z": round(float(z[i]), 2), "peak_value": float(x[i])})
    for iv in intervals:
        iv.pop("_last")
        iv["cause"] = "unknown"  # a statistical outlier says nothing about why it happened
    stats = {"n": len(x), "median": med, "mad": mad, "unit": unit or "unspecified", "sensor": sensor or "unspecified",
             "start": ts[0].isoformat(), "end": ts[-1].isoformat(), "method": f"robust z (MAD) > {z_threshold}",
             "anomaly_intervals": intervals, "provenance": "owner-supplied readings; calibration not verified"}
    p = ParsedIngest("sensor_csv", "MASINT", {"samples": len(x), "anomaly_intervals": len(intervals)},
                     access_class="OWNED_AUTHORIZED", mime="text/csv")
    p.observations.append(Obs("MASINT", "sensor.series_summary", stats, observed_at=ts[0], confidence="medium"))
    for iv in intervals:
        p.observations.append(Obs("MASINT", "sensor.anomaly_interval", {**iv, "unit": stats["unit"],
                                                                         "sensor": stats["sensor"]},
                                  observed_at=datetime.fromisoformat(iv["start"]), confidence="low"))
    if assumed_utc:
        p.warnings.append("Some timestamps had no timezone; UTC assumed.")
    return p


PARSERS = {"eml": parse_eml, "sigmf": parse_sigmf, "sensor_csv": parse_sensor_csv}
DETECTORS: list = []  # callables (filename, head) -> kind | None, registered by parser modules


def detect_kind(filename: str, head: bytes) -> str | None:
    name = filename.lower()
    for det in DETECTORS:
        k = det(name, head)
        if k:
            return k
    if name.endswith(".eml"):
        return "eml"
    if name.endswith(".sigmf"):
        return "sigmf"
    if name.endswith(".csv"):
        return "sensor_csv"
    if head[257:262] == b"ustar":
        return "sigmf"
    return None
