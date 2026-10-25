"""Image workbench: safe import, metadata, perceptual duplicate matching inside the case, and manual reverse-search bookkeeping.

What this module deliberately does NOT do: face detection, face embeddings, identity inference, OCR-based identification, or any call to a
reverse-image provider. A provider result is a *page where a similar image appears*, entered by a person, never an identification of anyone.
Files are decoded by Pillow only (no external tools, no network); nothing embedded in an image is fetched or executed.
"""
from __future__ import annotations

import io
import re
import warnings
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote, urlsplit

import numpy as np
from PIL import ExifTags, Image, UnidentifiedImageError
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db.models import Evidence, ImageAsset, ImageMatch, Subject
from ..evidence.vault import Vault
from ..telemetry import audit
from . import consent
from .service import ProfileError

ALLOWED_FORMATS = {"JPEG": "image/jpeg", "PNG": "image/png", "GIF": "image/gif", "WEBP": "image/webp", "BMP": "image/bmp", "TIFF": "image/tiff"}
MAX_BYTES = 25 * 1024 * 1024
MAX_PIXELS = 60_000_000
MAX_FRAMES = 200
DEFAULT_THRESHOLDS = {"phash_max": 6, "dhash_max": 10, "crop_max": 8}
LIMITS = ("Perceptual hashes find resized, recompressed and re-encoded copies and some crops. They do not find rotated, mirrored, heavily cropped or "
          "composited copies, and they can match different pictures that merely look alike. Every match needs a human decision.")
MATCH_TYPES = ("exact_duplicate", "near_duplicate", "possible_crop", "provider_page")
PROVIDERS = {
    "google_lens": {"name": "Google Lens", "url": "https://lens.google.com/uploadbyurl?url={u}", "home": "https://lens.google.com/"},
    "bing_visual": {"name": "Bing Visual Search", "url": "https://www.bing.com/images/search?view=detailv2&iss=sbi&q=imgurl:{u}", "home": "https://www.bing.com/visualsearch"},
    "tineye": {"name": "TinEye", "url": "https://tineye.com/search?url={u}", "home": "https://tineye.com/"},
}
_URLISH = re.compile(r"^https?://[^\s<>\"']{3,2000}$")
_TAGS = {v: k for k, v in ExifTags.TAGS.items()}
_GPS = {v: k for k, v in ExifTags.GPSTAGS.items()}
_SAFE_EXIF = ("Make", "Model", "Software", "DateTime", "Orientation", "Artist", "Copyright", "ImageDescription", "LensModel", "BodySerialNumber")
_SENSITIVE_EXIF = {"BodySerialNumber", "Artist"}      # device serials and personal names: held back from low-privilege views and exports


def _now() -> datetime:
    return datetime.now(UTC)


# ---- hashing (no external imaging libraries; numpy + Pillow only) --------------------------------------------------------------------------
def _gray(im: Image.Image, size: tuple[int, int]) -> np.ndarray:
    return np.asarray(im.convert("L").resize(size, Image.Resampling.LANCZOS), dtype=np.float64)


def _bits_to_hex(bits: np.ndarray) -> str:
    n = 0
    for b in bits.flatten():
        n = (n << 1) | int(b)
    return f"{n:016x}"


def ahash(im: Image.Image) -> str:
    a = _gray(im, (8, 8))
    return _bits_to_hex(a > a.mean())


def dhash(im: Image.Image) -> str:
    a = _gray(im, (9, 8))
    return _bits_to_hex(a[:, 1:] > a[:, :-1])


_N = 32
_DCT = np.array([[np.cos(np.pi * (2 * n + 1) * k / (2 * _N)) for n in range(_N)] for k in range(_N)])


def phash(im: Image.Image) -> str:
    a = _gray(im, (_N, _N))
    d = _DCT @ a @ _DCT.T
    low = d[:8, :8]
    med = np.median(low.flatten()[1:])        # the DC term is excluded from the threshold
    return _bits_to_hex(low > med)


def hamming(a: str, b: str) -> int:
    return (int(a, 16) ^ int(b, 16)).bit_count()


def _windows(w: int, h: int) -> list[tuple[int, int, int, int]]:
    """Sliding crop windows (50-95 % of each side, 5 % steps). A crop of the other image is found when one window lines up with it closely."""
    out: set[tuple[int, int, int, int]] = set()
    for pct in range(95, 49, -5):
        cw, ch = w * pct // 100, h * pct // 100
        xs = {w * k // 20 for k in range(20) if w * k // 20 + cw <= w} | {w - cw}
        ys = {h * k // 20 for k in range(20) if h * k // 20 + ch <= h} | {h - ch}
        out.update((x, y, x + cw, y + ch) for x in xs for y in ys)
    return sorted(out)


# ---- safe import --------------------------------------------------------------------------------------------------------------------------
def _to_deg(v: Any) -> float:
    d, m, s = (float(x) for x in v)
    return d + m / 60 + s / 3600


def _gps(exif: Image.Exif) -> dict[str, float] | None:
    try:
        g = exif.get_ifd(_TAGS["GPSInfo"])
    except Exception:
        return None
    try:
        lat, lon = _to_deg(g[_GPS["GPSLatitude"]]), _to_deg(g[_GPS["GPSLongitude"]])
        if g.get(_GPS["GPSLatitudeRef"], "N") == "S":
            lat = -lat
        if g.get(_GPS["GPSLongitudeRef"], "E") == "W":
            lon = -lon
    except (KeyError, TypeError, ValueError, ZeroDivisionError):
        return None
    if not (-90 <= lat <= 90 and -180 <= lon <= 180):
        return None
    out = {"lat": lat, "lon": lon}
    if _GPS["GPSAltitude"] in g:
        try:
            out["altitude_m"] = float(g[_GPS["GPSAltitude"]])
        except (TypeError, ValueError):
            pass
    return out


def _exif(im: Image.Image) -> tuple[dict[str, Any], dict[str, float] | None]:
    try:
        ex = im.getexif()
    except Exception:
        return {}, None
    out: dict[str, Any] = {}
    for name in _SAFE_EXIF:
        v = ex.get(_TAGS.get(name, -1))
        if v not in (None, ""):
            out[name] = str(v)[:200]
    try:
        sub = ex.get_ifd(_TAGS["ExifOffset"])
    except Exception:
        sub = {}
    for key in ("DateTimeOriginal", "DateTimeDigitized", "LensModel", "BodySerialNumber"):
        v = sub.get(_TAGS[key])
        if v not in (None, ""):
            out[key] = str(v)[:200]
    return out, _gps(ex)


def _trailing_data(data: bytes, fmt: str) -> int:
    if fmt == "PNG":
        i = data.rfind(b"IEND")
        return max(0, len(data) - (i + 8)) if i != -1 else 0
    if fmt == "JPEG":
        i = data.rfind(b"\xff\xd9")
        return max(0, len(data) - (i + 2)) if i != -1 else 0
    return 0


def inspect(data: bytes) -> dict[str, Any]:
    """Decode with Pillow under hard limits. Raises ProfileError for anything that is not a plain raster image."""
    if not data:
        raise ProfileError("empty_file", "the file is empty")
    if len(data) > MAX_BYTES:
        raise ProfileError("too_large", f"images are limited to {MAX_BYTES // (1024 * 1024)} MB")
    head = data[:64].lstrip().lower()
    if head.startswith((b"<svg", b"<?xml", b"<!doctype", b"<html", b"%pdf", b"mz", b"pk\x03\x04")) or b"<script" in data[:2048].lower():
        raise ProfileError("unsafe_file", "this is not a plain raster image (SVG, HTML, PDF, archives and executables are refused)")
    old = Image.MAX_IMAGE_PIXELS
    Image.MAX_IMAGE_PIXELS = MAX_PIXELS
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            try:
                probe = Image.open(io.BytesIO(data))
                fmt = probe.format or ""
                if fmt not in ALLOWED_FORMATS:
                    raise ProfileError("unsupported_format", f"format {fmt or 'unknown'} is not accepted (allowed: {', '.join(ALLOWED_FORMATS)})")
                probe.verify()                                     # structural check without decoding all pixels
                im = Image.open(io.BytesIO(data))
                frames = getattr(im, "n_frames", 1)
                if frames > MAX_FRAMES:
                    raise ProfileError("too_many_frames", f"animated images are limited to {MAX_FRAMES} frames")
                im.load()
            except (UnidentifiedImageError, OSError, SyntaxError, ValueError, Image.DecompressionBombError, Image.DecompressionBombWarning) as exc:
                raise ProfileError("invalid_image", f"the file could not be read as an image ({type(exc).__name__})") from exc
    finally:
        Image.MAX_IMAGE_PIXELS = old
    if im.width * im.height > MAX_PIXELS:
        raise ProfileError("too_large", "image dimensions are too large")
    exif, gps = _exif(im)
    rgb = im.convert("RGB")
    crops = [phash(rgb.crop(box)) for box in _windows(*rgb.size)] if min(rgb.size) >= 64 else []
    trailing = _trailing_data(data, fmt)
    text_keys = sorted(str(k)[:40] for k in (im.info or {}) if isinstance(k, str) and k.lower() not in ("dpi", "icc_profile", "exif", "transparency", "gamma"))[:20]
    notes = ["Metadata can be missing, stripped or forged; treat it as a lead."]
    if trailing > 16:
        notes.append(f"{trailing} bytes follow the end of the image data (possible appended content). They are kept only in the original evidence and are excluded from derived copies.")
    return {"format": fmt, "width": im.width, "height": im.height, "frames": frames, "ahash": ahash(rgb), "dhash": dhash(rgb), "phash": phash(rgb), "crop_phashes": crops,
            "exif": exif, "gps": gps, "has_gps": gps is not None, "embedded_text_keys": text_keys, "trailing_bytes": trailing, "notes": notes, "mode": im.mode}


def sanitized_png(data: bytes, max_side: int = 512) -> bytes:
    """A pixel-only derived copy: re-encoded, no metadata, no appended bytes, downscaled. This is what the UI previews."""
    info = inspect(data)
    del info
    im = Image.open(io.BytesIO(data))
    im.seek(0)
    rgb = im.convert("RGB")
    rgb.thumbnail((max_side, max_side))
    out = io.BytesIO()
    rgb.save(out, format="PNG")
    return out.getvalue()


def import_image(db: Session, vault: Vault, subject: Subject, data: bytes, filename: str, *, ownership: str, source_url: str | None, actor: str) -> tuple[ImageAsset, bool]:
    consent.require(db, subject, "image_analysis")
    if ownership not in ("user_owned", "public", "authorized"):
        raise ProfileError("invalid_ownership", "ownership must be user_owned, public or authorized")
    if source_url:
        source_url = source_url.strip()
        if not _URLISH.match(source_url) or urlsplit(source_url).username:
            raise ProfileError("invalid_url", "the source URL must be a plain http(s) address without credentials")
    info = inspect(data)
    sha256, sha512, rel, size = vault.store(data)
    existing = db.scalars(select(ImageAsset).where(ImageAsset.subject_id == subject.id, ImageAsset.sha256 == sha256)).first()
    if existing:
        return existing, False
    now = _now()
    ev = db.scalars(select(Evidence).where(Evidence.case_id == subject.case_id, Evidence.sha256 == sha256, Evidence.kind == "import.image")).first()
    if ev is None:
        safe = re.sub(r"[^\w.\- ]", "_", filename.replace("\\", "/").split("/")[-1])[:120] or "image"
        ev = Evidence(case_id=subject.case_id, kind="import.image", title=safe, sha256=sha256, sha512=sha512, byte_size=size, mime_type=ALLOWED_FORMATS[info["format"]],
                      vault_relpath=rel, retrieved_at=now, observed_at=now, capture_method="manual_import", sensitivity="RESTRICTED", created_by=actor,
                      original_url=source_url, description="Image import; decoded only by Pillow, stored inert, never executed or fetched from.",
                      chain_of_custody_json=[{"event": "imported", "at": now.isoformat(), "by": actor, "sha256": sha256, "ownership": ownership}])
        db.add(ev)
        db.flush()
    meta = {"exif": info["exif"], "gps": info["gps"], "embedded_text_keys": info["embedded_text_keys"], "trailing_bytes": info["trailing_bytes"], "notes": info["notes"],
            "crop_phashes": info["crop_phashes"], "frames": info["frames"], "limits": LIMITS}
    asset = ImageAsset(subject_id=subject.id, case_id=subject.case_id, evidence_id=ev.id, sha256=sha256, phash=info["phash"], dhash=info["dhash"], ahash=info["ahash"],
                       width=info["width"], height=info["height"], format=info["format"], ownership=ownership, source_url=source_url, metadata_json=meta, has_gps=info["has_gps"])
    db.add(asset)
    db.flush()
    audit.record(db, "image.import", actor=actor, case_id=subject.case_id, resource_type="image_asset", resource_id=asset.id,
                 metadata={"format": info["format"], "has_gps": info["has_gps"], "ownership": ownership})
    match_local(db, asset)
    return asset, True


# ---- local matching ---------------------------------------------------------------------------------------------------------------------
def match_local(db: Session, asset: ImageAsset, thresholds: dict[str, int] | None = None) -> list[ImageMatch]:
    """Compare against other images already held in THIS case. Review decisions on existing pairs are never overwritten."""
    th = {**DEFAULT_THRESHOLDS, **(thresholds or {})}
    others = list(db.scalars(select(ImageAsset).where(ImageAsset.case_id == asset.case_id, ImageAsset.id != asset.id)))
    known = {(m.other_asset_id, m.match_type): m for m in db.scalars(select(ImageMatch).where(ImageMatch.asset_id == asset.id, ImageMatch.other_asset_id.is_not(None)))}
    # a rejected pair stays rejected whatever type a later run assigns it
    rejected = {m.other_asset_id for m in known.values() if m.review_state == "rejected"}
    made: list[ImageMatch] = []
    for o in others:
        if o.id in rejected:
            continue
        kind: str | None = None
        dist: float = 0
        if o.sha256 == asset.sha256:
            kind, dist = "exact_duplicate", 0
        else:
            dp, dd = hamming(asset.phash, o.phash), hamming(asset.dhash, o.dhash)
            if dp <= th["phash_max"] and dd <= th["dhash_max"]:
                kind, dist = "near_duplicate", float(dp)
            else:
                best = min([hamming(asset.phash, c) for c in (o.metadata_json.get("crop_phashes") or [])]
                           + [hamming(o.phash, c) for c in (asset.metadata_json.get("crop_phashes") or [])] or [64])
                if best <= th["crop_max"]:
                    kind, dist = "possible_crop", float(best)
        if kind is None or (o.id, kind) in known:
            continue
        m = ImageMatch(asset_id=asset.id, subject_id=asset.subject_id, case_id=asset.case_id, other_asset_id=o.id, match_type=kind, distance=dist,
                       score=round(1 - dist / 64, 3), evidence_ids=[asset.evidence_id, o.evidence_id],
                       note={"exact_duplicate": "Identical file content (same SHA-256).", "near_duplicate": "Looks like a resized, recompressed or re-encoded copy; confirm visually.",
                             "possible_crop": "Might be a crop of the other image; this is the least reliable match type."}[kind])
        db.add(m)
        made.append(m)
    db.flush()
    return made


def reverse_search_guide(asset: ImageAsset) -> dict[str, Any]:
    """Manual provider flow. Builds link-out addresses only; nothing is sent from this application and nothing is scraped."""
    public = asset.source_url if asset.ownership == "public" and asset.source_url else None
    providers = []
    for pid, p in PROVIDERS.items():
        providers.append({"id": pid, "name": p["name"], "home": p["home"], "link": p["url"].format(u=quote(public, safe="")) if public else None,
                          "how": (f"Open the link; the provider receives the image address {public}." if public else
                                  f"Open {p['home']} yourself and upload the image file there. This application never uploads it for you."),
                          "automation": "none: the provider offers interactive or commercial access only; no unattended calls, scraping or CAPTCHA handling are attempted"})
    return {"asset_id": asset.id, "public_url_known": bool(public), "providers": providers,
            "steps": ["Decide whether it is acceptable for the provider to see this image (opening a link or uploading discloses it to that provider).",
                      "Run the search in your own browser.",
                      "For each result page that really shows this image, record its address, the provider and the date here.",
                      "A result is a page where a similar or identical image appears. It does not identify the person shown, and absent results prove nothing."],
            "limits": "Do not infer who a person is from how a face looks. Record publication pages and duplicates only."}


def record_provider_result(db: Session, asset: ImageAsset, *, provider: str, matched_url: str, note: str, actor: str, screenshot_evidence_id: str | None = None) -> ImageMatch:
    if provider not in (*PROVIDERS, "other"):
        raise ProfileError("invalid_provider", f"provider must be one of {', '.join([*PROVIDERS, 'other'])}")
    matched_url = matched_url.strip()
    if not _URLISH.match(matched_url) or urlsplit(matched_url).username:
        raise ProfileError("invalid_url", "enter the result page address as a plain http(s) URL")
    ev = [asset.evidence_id]
    if screenshot_evidence_id:
        e = db.get(Evidence, screenshot_evidence_id)
        if not e or e.case_id != asset.case_id:
            raise ProfileError("evidence_not_in_case", "screenshot evidence is not in this case")
        ev.append(e.id)
    m = ImageMatch(asset_id=asset.id, subject_id=asset.subject_id, case_id=asset.case_id, match_type="provider_page", provider=provider, matched_url=matched_url,
                   note=note.strip()[:1000], evidence_ids=ev, observed_at=_now(), review_state="candidate")
    db.add(m)
    db.flush()
    audit.record(db, "image.provider_result", actor=actor, case_id=asset.case_id, resource_type="image_match", resource_id=m.id, metadata={"provider": provider})
    return m


def review_match(db: Session, subject: Subject, match_id: str, *, state: str, reviewer: str, note: str) -> ImageMatch:
    m = db.get(ImageMatch, match_id)
    if not m or m.subject_id != subject.id:
        raise ProfileError("not_found", "match not found")
    if state not in ("candidate", "confirmed_same_image", "rejected", "unsure"):
        raise ProfileError("invalid_state", "state must be confirmed_same_image, rejected, unsure or candidate")
    if not note.strip():
        raise ProfileError("basis_required", "say why (for example 'different photo of a similar scene')")
    m.review_state, m.reviewer, m.note = state, reviewer, f"{note.strip()[:800]}"
    audit.record(db, "image.match_review", actor=reviewer, case_id=subject.case_id, resource_type="image_match", resource_id=m.id, metadata={"state": state})
    return m


# ---- privacy-aware views ----------------------------------------------------------------------------------------------------------------
def coarse(v: float) -> float:
    return round(v, 1)       # ~11 km: enough to say "this region", not enough to find a house


def asset_dict(a: ImageAsset, *, role: str, precise_allowed: bool | None = None) -> dict[str, Any]:
    precise = (role in ("owner", "editor")) if precise_allowed is None else precise_allowed
    meta = a.metadata_json or {}
    exif = {k: v for k, v in (meta.get("exif") or {}).items() if precise or k not in _SENSITIVE_EXIF}
    gps = meta.get("gps")
    gps_out = None
    if gps:
        gps_out = {"lat": gps["lat"], "lon": gps["lon"], "altitude_m": gps.get("altitude_m"), "precision": "exact"} if precise else \
            {"lat": coarse(gps["lat"]), "lon": coarse(gps["lon"]), "precision": "coarse (about 10 km)"}
    return {"id": a.id, "evidence_id": a.evidence_id, "sha256": a.sha256, "format": a.format, "width": a.width, "height": a.height, "ownership": a.ownership,
            "source_url": a.source_url, "has_gps": a.has_gps, "gps": gps_out, "exif": exif, "notes": meta.get("notes", []), "frames": meta.get("frames", 1),
            "hashes": {"phash": a.phash, "dhash": a.dhash, "ahash": a.ahash}, "created_at": a.created_at, "limits": meta.get("limits", LIMITS),
            "metadata_caveat": "Metadata can be missing, removed or forged."}


def match_dict(db: Session, m: ImageMatch) -> dict[str, Any]:
    from .service import evidence_refs
    other = db.get(ImageAsset, m.other_asset_id) if m.other_asset_id else None
    return {"id": m.id, "asset_id": m.asset_id, "other_asset_id": m.other_asset_id, "type": m.match_type, "provider": m.provider, "matched_url": m.matched_url,
            "distance": m.distance, "score": m.score, "state": m.review_state, "reviewer": m.reviewer, "note": m.note, "observed_at": m.observed_at,
            "evidence": evidence_refs(db, m.evidence_ids), "other_sha256": other.sha256 if other else None,
            "confidence_note": ("Provider results are pages where a similar image appears, entered by a person; they do not identify anyone." if m.match_type == "provider_page"
                                else LIMITS)}
