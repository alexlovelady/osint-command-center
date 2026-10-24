"""GEOINT/IMINT importers (spec 21): EXIF GPS, GeoTIFF metadata, PNG decode, pixel-difference change detection.

Everything is pure Python + numpy and reads bytes only. EXIF positions are *claims made by a file* (trivially editable);
accuracy is "unknown" unless the file states it. A pixel difference is never reported as a verified real-world event.
"""
from __future__ import annotations

import math
import struct
import zlib
from datetime import UTC, datetime
from typing import Any, ClassVar

import numpy as np

from .parsers import DETECTORS, PARSERS, IngestError, Obs, ParsedIngest

PARSER_GEO = "1.0.0"
MAX_PIXELS = 1_000_000  # pure-Python PNG decode is bounded on purpose


# ------------------------------------------------------------------ EXIF ------------------------------------------
class _Tiff:
    TYPES: ClassVar[dict[int, tuple[str, int]]] = {1: ("B", 1), 2: ("c", 1), 3: ("H", 2), 4: ("I", 4), 5: ("II", 8),
                                                    6: ("b", 1), 7: ("B", 1), 8: ("h", 2), 9: ("i", 4), 10: ("ii", 8),
                                                    11: ("f", 4), 12: ("d", 8)}

    def __init__(self, data: bytes):
        if data[:2] == b"II":
            self.e = "<"
        elif data[:2] == b"MM":
            self.e = ">"
        else:
            raise IngestError("bad TIFF byte order")
        self.d = data
        if self._u("H", 2) != 42:
            raise IngestError("bad TIFF magic")

    def _u(self, fmt: str, off: int):
        size = struct.calcsize(fmt)
        if off < 0 or off + size > len(self.d):
            raise IngestError("EXIF offset out of range")
        return struct.unpack_from(self.e + fmt, self.d, off)[0]

    def ifd(self, off: int, depth: int = 0) -> dict[int, Any]:
        if depth > 2:
            raise IngestError("EXIF IFD nesting too deep")
        n = self._u("H", off)
        if n > 512:
            raise IngestError("implausible EXIF entry count")
        out: dict[int, Any] = {}
        for i in range(n):
            base = off + 2 + 12 * i
            tag, typ, count = self._u("H", base), self._u("H", base + 2), self._u("I", base + 4)
            if typ not in self.TYPES or count > 4096:
                continue
            fmt, unit = self.TYPES[typ]
            total = unit * count
            voff = base + 8 if total <= 4 else self._u("I", base + 8)
            if voff < 0 or voff + total > len(self.d):
                continue
            raw = self.d[voff:voff + total]
            if typ == 2:
                out[tag] = raw.split(b"\x00")[0].decode("latin-1")
            elif typ in (5, 10):
                vals = struct.unpack(self.e + fmt[0] * (2 * count), raw)
                out[tag] = [vals[j] / vals[j + 1] if vals[j + 1] else float("nan") for j in range(0, len(vals), 2)]
            elif typ in (1, 7):
                out[tag] = list(raw)
            else:
                out[tag] = list(struct.unpack(self.e + fmt * count, raw))
        return out


def _dms(v, ref) -> float | None:
    if not v or len(v) != 3 or any(math.isnan(x) for x in v):
        return None
    deg = v[0] + v[1] / 60 + v[2] / 3600
    return -deg if ref in ("S", "W") else deg


def parse_jpeg_exif(data: bytes) -> ParsedIngest:
    if data[:2] != b"\xff\xd8":
        raise IngestError("not a JPEG")
    pos, tiff = 2, None
    while pos + 4 <= len(data):
        if data[pos] != 0xFF:
            break
        marker, seglen = data[pos + 1], struct.unpack(">H", data[pos + 2:pos + 4])[0]
        if marker in (0xDA, 0xD9):
            break
        if marker == 0xE1 and data[pos + 4:pos + 10] == b"Exif\x00\x00":
            tiff = data[pos + 10:pos + 2 + seglen]
            break
        pos += 2 + seglen
    info: dict[str, Any] = {"has_exif": tiff is not None, "has_gps": False}
    obs_time = None
    warnings: list[str] = ["EXIF metadata is trivially editable; treat as a claim made by the file, not as proof."]
    if tiff:
        t = _Tiff(tiff)
        ifd0 = t.ifd(t._u("I", 4))
        info.update({"make": ifd0.get(0x010F), "model": ifd0.get(0x0110), "software": ifd0.get(0x0131)})
        exif = t.ifd(ifd0[0x8769][0]) if 0x8769 in ifd0 else {}
        local = exif.get(0x9003) or ifd0.get(0x0132)
        info["local_time_text"] = local  # no timezone in EXIF; kept verbatim, never treated as UTC
        if 0x8825 in ifd0:
            g = t.ifd(ifd0[0x8825][0])
            lat, lon = _dms(g.get(2), g.get(1)), _dms(g.get(4), g.get(3))
            if lat is not None and lon is not None and abs(lat) <= 90 and abs(lon) <= 180:
                alt = g.get(6, [None])[0]
                if alt is not None and g.get(5, [0])[0] == 1:
                    alt = -alt
                acc = g.get(31, [None])[0]
                info.update({"has_gps": True, "location": {
                    "lat": round(lat, 7), "lon": round(lon, 7), "crs": "EPSG:4326",
                    "accuracy_m": None if (acc is None or math.isnan(acc)) else acc, "altitude_m": alt,
                    "accuracy_note": "stated by the file" if acc else "unknown: EXIF did not state accuracy"}})
                if g.get(7) and g.get(29):
                    try:
                        h, m, s = (int(x) for x in g[7])
                        obs_time = datetime.strptime(g[29], "%Y:%m:%d").replace(hour=h, minute=m, second=s, tzinfo=UTC)
                    except (ValueError, TypeError):
                        pass
    if not info["has_gps"]:
        warnings.append("No usable GPS position in this image.")
    if info.get("local_time_text") and obs_time is None:
        warnings.append("Capture time has no timezone; observed_at is unknown (local text kept).")
    p = ParsedIngest("jpeg_exif", "GEOINT", {"has_gps": info["has_gps"], "make": info.get("make")}, warnings=warnings,
                     mime="image/jpeg", access_class="IMPORTED")
    p.observations.append(Obs("GEOINT", "geo.exif_position" if info["has_gps"] else "media.exif", info,
                              observed_at=obs_time, confidence="low" if info["has_gps"] else "unknown",
                              sensitivity="RESTRICTED" if info["has_gps"] else "INTERNAL"))
    return p


# ------------------------------------------------------------------ GeoTIFF ---------------------------------------
def parse_geotiff(data: bytes) -> ParsedIngest:
    t = _Tiff(data)
    if data[2:4] in (b"\x2b\x00", b"\x00\x2b"):
        raise IngestError("BigTIFF is not supported")
    ifd = t.ifd(t._u("I", 4))
    w = ifd.get(256, [None])[0]
    h = ifd.get(257, [None])[0]
    if not w or not h or w > 1_000_000 or h > 1_000_000:
        raise IngestError("missing or implausible raster dimensions")
    scale, tie, keys = ifd.get(33550), ifd.get(33922), ifd.get(34735)
    if not (scale and tie and keys and len(scale) >= 2 and len(tie) >= 6):
        raise IngestError("not a GeoTIFF (missing ModelPixelScale/ModelTiepoint/GeoKeyDirectory)")
    kd = {keys[4 + 4 * i]: keys[7 + 4 * i] for i in range(min(keys[3], (len(keys) - 4) // 4))}
    epsg = kd.get(2048) or kd.get(3072)
    crs = f"EPSG:{epsg}" if epsg and epsg < 32767 else None
    x0, y0 = tie[3] - tie[0] * scale[0], tie[4] + tie[1] * scale[1]
    bounds = {"min_x": x0, "max_x": x0 + w * scale[0], "min_y": y0 - h * scale[1], "max_y": y0}
    geographic = crs == "EPSG:4326"
    pixel_m = scale[0] * 111_320 if geographic else (scale[0] if crs else None)
    acq = None
    warnings = ["Bounds are in the file's native CRS; no reprojection or georeferencing quality check was performed."]
    if not crs:
        warnings.append("CRS could not be determined from GeoKeys; do not overlay on a map.")
    if ifd.get(306):
        warnings.append("DateTime tag present but has no timezone; acquisition time is not asserted.")
    info = {"width": w, "height": h, "crs": crs, "bounds": bounds, "pixel_size_native_units": scale[0],
            "approx_pixel_size_m": pixel_m, "model_type": kd.get(1024), "raster_type": kd.get(1025),
            "datetime_text": ifd.get(306),
            "licence": "UNKNOWN: verify the imagery licence before redistribution or export"}
    precision = "UNKNOWN" if pixel_m is None else ("FINE" if pixel_m <= 5 else "COARSE")
    p = ParsedIngest("geotiff", "GEOINT", {"crs": crs, "width": w, "height": h}, warnings=warnings,
                     mime="image/tiff", access_class="IMPORTED")
    p.observations.append(Obs("GEOINT", "geo.raster_metadata", info, observed_at=acq, confidence="medium"))
    p.layers.append({"coordinate_system": crs, "bounds_json": bounds, "acquisition_time": acq,
                     "imagery_licence": info["licence"], "precision_class": precision, "pixel_size": pixel_m,
                     "width": w, "height": h})
    return p


# ------------------------------------------------------------------ PNG codec -------------------------------------
def decode_png(data: bytes) -> np.ndarray:
    """8-bit non-interlaced PNG (gray, RGB, gray+alpha, RGBA) -> HxWxC uint8. Bounded to MAX_PIXELS."""
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        raise IngestError("not a PNG")
    pos, ihdr, idat = 8, None, bytearray()
    while pos + 8 <= len(data):
        ln, typ = struct.unpack(">I4s", data[pos:pos + 8])
        body = data[pos + 8:pos + 8 + ln]
        if len(body) != ln:
            raise IngestError("truncated PNG chunk")
        crc = data[pos + 8 + ln:pos + 12 + ln]
        if len(crc) != 4:
            raise IngestError("truncated PNG chunk")
        if zlib.crc32(typ + body) & 0xFFFFFFFF != struct.unpack(">I", crc)[0]:
            raise IngestError("PNG chunk CRC mismatch")
        if typ == b"IHDR":
            ihdr = struct.unpack(">IIBBBBB", body)
        elif typ == b"IDAT":
            idat += body
        elif typ == b"IEND":
            break
        pos += 12 + ln
    if not ihdr:
        raise IngestError("PNG has no IHDR")
    w, h, depth, ctype, _, _, interlace = ihdr
    if depth != 8 or interlace != 0 or ctype not in (0, 2, 4, 6):
        raise IngestError("only 8-bit non-interlaced gray/RGB/RGBA PNG is supported")
    if w * h > MAX_PIXELS or w == 0 or h == 0:
        raise IngestError(f"image exceeds the {MAX_PIXELS}-pixel analysis limit")
    ch = {0: 1, 2: 3, 4: 2, 6: 4}[ctype]
    stride = w * ch
    try:
        raw = zlib.decompressobj().decompress(bytes(idat), stride * h + h + 1)
    except zlib.error as exc:
        raise IngestError("corrupt PNG data") from exc
    if len(raw) != (stride + 1) * h:
        raise IngestError("PNG data length mismatch")
    out = np.zeros((h, stride), dtype=np.uint8)
    prev = np.zeros(stride, dtype=np.int32)
    for y in range(h):
        f = raw[y * (stride + 1)]
        line = np.frombuffer(raw, dtype=np.uint8, count=stride, offset=y * (stride + 1) + 1).astype(np.int32)
        if f == 0:
            cur = line
        elif f == 1:
            cur = line.copy()
            for c in range(ch):
                cur[c::ch] = np.cumsum(line[c::ch]) % 256
        elif f == 2:
            cur = (line + prev) % 256
        elif f == 3:
            cur = line.copy()
            for i in range(stride):
                left = cur[i - ch] if i >= ch else 0
                cur[i] = (line[i] + ((left + prev[i]) >> 1)) % 256
        elif f == 4:
            cur = line.copy()
            for i in range(stride):
                a = cur[i - ch] if i >= ch else 0
                b = prev[i]
                c = prev[i - ch] if i >= ch else 0
                pa, pb, pc = abs(b - c), abs(a - c), abs(a + b - 2 * c)
                pred = a if pa <= pb and pa <= pc else (b if pb <= pc else c)
                cur[i] = (line[i] + pred) % 256
        else:
            raise IngestError("bad PNG filter")
        out[y] = cur
        prev = cur
    return out.reshape(h, w, ch)


def encode_png(arr: np.ndarray) -> bytes:
    a = np.ascontiguousarray(arr.astype(np.uint8))
    if a.ndim == 2:
        a = a[:, :, None]
    h, w, ch = a.shape
    ctype = {1: 0, 2: 4, 3: 2, 4: 6}[ch]
    raw = b"".join(b"\x00" + a[y].tobytes() for y in range(h))

    def chunk(t: bytes, d: bytes) -> bytes:
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, ctype, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw, 6)) + chunk(b"IEND", b""))


def change_detection(before: bytes, after: bytes, threshold: int = 30, min_region_px: int = 4) -> dict[str, Any]:
    """Absolute luminance difference between two same-size images. No registration, no interpretation."""
    a, b = decode_png(before), decode_png(after)
    if a.shape[:2] != b.shape[:2]:
        raise IngestError(f"image sizes differ ({a.shape[1]}x{a.shape[0]} vs {b.shape[1]}x{b.shape[0]}); "
                          "automatic resampling/registration is not performed")
    if not 1 <= threshold <= 255:
        raise IngestError("threshold must be 1..255")

    def lum(x):
        x = x.astype(np.float32)
        return x[..., 0] if x.shape[2] <= 2 else 0.299 * x[..., 0] + 0.587 * x[..., 1] + 0.114 * x[..., 2]
    diff = np.abs(lum(a) - lum(b))
    mask = diff > threshold
    n = int(mask.sum())
    box = None
    if n >= min_region_px:
        ys, xs = np.nonzero(mask)
        box = {"x0": int(xs.min()), "y0": int(ys.min()), "x1": int(xs.max()), "y1": int(ys.max())}
    else:
        mask[:] = False
        n = 0
    vis = np.zeros(a.shape[:2] + (3,), dtype=np.uint8)
    vis[..., 0] = np.clip(diff * 2, 0, 255).astype(np.uint8)
    vis[mask] = (255, 40, 40)
    return {"changed_pixels": n, "total_pixels": int(mask.size), "changed_fraction": n / mask.size, "threshold": threshold,
            "bounding_box": box, "image_size": {"width": int(a.shape[1]), "height": int(a.shape[0])},
            "interpretation": "pixel difference only: lighting, season, sensor and registration effects are not "
                              "excluded and this is NOT a verified real-world event",
            "_png": encode_png(vis)}


def _detect(name: str, head: bytes) -> str | None:
    if head[:2] == b"\xff\xd8":
        return "jpeg_exif"
    if head[:4] in (b"II*\x00", b"MM\x00*") and name.endswith((".tif", ".tiff", ".gtiff")):
        return "geotiff"
    return None


PARSERS["jpeg_exif"] = parse_jpeg_exif
PARSERS["geotiff"] = parse_geotiff
DETECTORS.append(_detect)
