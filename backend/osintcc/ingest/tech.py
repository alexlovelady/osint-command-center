"""TECHINT importers: CycloneDX/SPDX SBOMs and static firmware inspection (spec 21.1, 21.8 #9).

Static analysis only. Nothing in this module executes, unpacks-and-runs, or emulates an artifact; there is no subprocess
call at all. Hostile binaries are bytes to be measured.
"""
from __future__ import annotations

import json
import math
import re
from collections import Counter
from typing import Any

from .parsers import DETECTORS, PARSERS, EntityDraft, IngestError, Obs, ParsedIngest, RelDraft

MAX_COMPONENTS = 50_000


def _comp_key(name: str, version: str | None, purl: str | None) -> str:
    return (purl or f"{name}@{version}" if version else purl or name)[:300]


def parse_cyclonedx(data: bytes) -> ParsedIngest:
    try:
        bom = json.loads(data)
    except ValueError as exc:
        raise IngestError("not valid JSON") from exc
    if not isinstance(bom, dict):
        raise IngestError("not a CycloneDX BOM")
    if bom.get("bomFormat") == "CycloneDX":
        return _cdx(bom)
    if str(bom.get("spdxVersion", "")).startswith("SPDX-"):
        return _spdx(bom)
    raise IngestError("neither a CycloneDX nor an SPDX JSON document")


def _cdx(bom: dict) -> ParsedIngest:
    comps = bom.get("components")
    if not isinstance(comps, list) or not comps:
        raise IngestError("CycloneDX BOM has no components")
    if len(comps) > MAX_COMPONENTS:
        raise IngestError("too many components")
    p = ParsedIngest("sbom", "TECHINT", {}, mime="application/vnd.cyclonedx+json", access_class="OWNED_AUTHORIZED")
    ref_key: dict[str, str] = {}
    listed = []
    for c in comps:
        if not isinstance(c, dict) or not c.get("name"):
            continue
        name, ver, purl = str(c["name"])[:200], str(c.get("version", ""))[:80] or None, str(c.get("purl", ""))[:300] or None
        key = _comp_key(name, ver, purl)
        ref_key[str(c.get("bom-ref", key))] = key
        lic = []
        for lc in c.get("licenses", []) if isinstance(c.get("licenses"), list) else []:
            if isinstance(lc, dict):
                lic.append((lc.get("license") or {}).get("id") or (lc.get("license") or {}).get("name") or lc.get("expression"))
        hashes = {h.get("alg"): h.get("content") for h in c.get("hashes", []) if isinstance(h, dict)}
        p.entities.append(EntityDraft("component", key, f"{name} {ver}" if ver else name))
        listed.append({"name": name, "version": ver, "purl": purl, "type": c.get("type"),
                       "licenses": [x for x in lic if x], "hashes": hashes,
                       "supplier": (c.get("supplier") or {}).get("name") if isinstance(c.get("supplier"), dict) else None})
    for d in bom.get("dependencies", []) if isinstance(bom.get("dependencies"), list) else []:
        a = ref_key.get(str(d.get("ref"))) if isinstance(d, dict) else None
        for dep in (d.get("dependsOn", []) if isinstance(d, dict) else []):
            b = ref_key.get(str(dep))
            if a and b and a != b:
                p.relationships.append(RelDraft(("component", a), ("component", b), "depends_on",
                                                "declared in the supplied SBOM (not verified against the real build)"))
    meta = bom.get("metadata", {}) if isinstance(bom.get("metadata"), dict) else {}
    top = meta.get("component") if isinstance(meta.get("component"), dict) else None
    if top and top.get("name"):
        tk = _comp_key(str(top["name"]), str(top.get("version", "")) or None, top.get("purl"))
        p.entities.append(EntityDraft("component", tk, f"{top['name']} {top.get('version', '')}".strip()))
        for k in ref_key.values():
            if k != tk:
                p.relationships.append(RelDraft(("component", tk), ("component", k), "contains",
                                                "listed as a component of the described product in the SBOM"))
    p.summary = {"format": "CycloneDX", "spec_version": bom.get("specVersion"), "components": len(listed)}
    p.observations.append(Obs("TECHINT", "sbom.components", {"format": "CycloneDX", "spec_version": bom.get("specVersion"),
                                                           "components": listed[:2000], "total": len(listed),
                                                           "note": "declared by the supplier; completeness is unverified"},
                              observed_at=None, confidence="medium"))
    return p


def _spdx(doc: dict) -> ParsedIngest:
    pk = doc.get("packages")
    if not isinstance(pk, list) or not pk:
        raise IngestError("SPDX document has no packages")
    p = ParsedIngest("sbom", "TECHINT", {}, mime="application/spdx+json", access_class="OWNED_AUTHORIZED")
    ids, listed = {}, []
    for c in pk[:MAX_COMPONENTS]:
        if not isinstance(c, dict) or not c.get("name"):
            continue
        key = _comp_key(str(c["name"])[:200], str(c.get("versionInfo", ""))[:80] or None, None)
        ids[c.get("SPDXID")] = key
        p.entities.append(EntityDraft("component", key, key))
        listed.append({"name": c["name"], "version": c.get("versionInfo"), "license": c.get("licenseConcluded"),
                       "download": c.get("downloadLocation")})
    for r in doc.get("relationships", []) if isinstance(doc.get("relationships"), list) else []:
        if isinstance(r, dict) and r.get("relationshipType") in ("DEPENDS_ON", "CONTAINS"):
            a, b = ids.get(r.get("spdxElementId")), ids.get(r.get("relatedSpdxElement"))
            if a and b and a != b:
                p.relationships.append(RelDraft(("component", a), ("component", b),
                                                "depends_on" if r["relationshipType"] == "DEPENDS_ON" else "contains",
                                                "declared in the supplied SPDX document"))
    p.summary = {"format": "SPDX", "components": len(listed)}
    p.observations.append(Obs("TECHINT", "sbom.components", {"format": "SPDX", "components": listed[:2000], "total": len(listed)},
                              confidence="medium"))
    return p


# ------------------------------------------------------------------ firmware ------------------------------------
_MAGIC = [(b"\x1f\x8b\x08", "gzip"), (b"PK\x03\x04", "zip"), (b"hsqs", "squashfs-le"), (b"sqsh", "squashfs-be"),
          (b"\x7fELF", "elf"), (b"\x27\x05\x19\x56", "uboot-uimage"), (b"070701", "cpio-newc"), (b"BZh", "bzip2"),
          (b"\xfd7zXZ\x00", "xz"), (b"\x89PNG\r\n\x1a\n", "png"), (b"\xff\xd8\xff", "jpeg"), (b"\x85\x19", "jffs2"),
          (b"UBI#", "ubi"), (b"\xd0\x0d\xfe\xed", "devicetree"), (b"MZ", "dos-pe")]
_STR = re.compile(rb"[\x20-\x7e]{6,200}")
_URL = re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{4,200}")
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,100}\.[A-Za-z]{2,}")
_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_VERSION = re.compile(r"(BusyBox v[\d.]+|OpenSSL \d[\w.]+|Linux version [\d.]+[\w.-]*|U-Boot [\d.]+[\w.-]*|"
                      r"dropbear[_ ][\d.]+|lighttpd/[\d.]+|uClibc[- ]?[\d.]+)", re.IGNORECASE)
_CRED = re.compile(r"(passw(?:or)?d|passwd|secret|api[_-]?key|token|private key)\s*[=:]", re.IGNORECASE)


def shannon(b: bytes) -> float:
    if not b:
        return 0.0
    n = len(b)
    return -sum(c / n * math.log2(c / n) for c in Counter(b).values())


def parse_firmware(data: bytes) -> ParsedIngest:
    if len(data) < 16:
        raise IngestError("file too small to analyse")
    block = 65536
    prof = [round(shannon(data[i:i + block]), 2) for i in range(0, min(len(data), 64 * block), block)]
    sigs: list[dict[str, Any]] = []
    for magic, name in _MAGIC:
        start, hits = 0, 0
        while hits < 20:
            i = data.find(magic, start)
            if i < 0:
                break
            if not (name == "dos-pe" and i != 0) and not (name == "jffs2" and i % 4):
                sigs.append({"offset": i, "signature": name})
                hits += 1
            start = i + 1
    sigs.sort(key=lambda s: s["offset"])
    strings = [m.group().decode("ascii") for m in _STR.finditer(data[:16 * 1024 * 1024])][:20000]
    blob = "\n".join(strings)
    urls = sorted(set(_URL.findall(blob)))[:100]
    emails = sorted(set(_EMAIL.findall(blob)))[:50]
    ips = sorted({i for i in _IPV4.findall(blob) if not i.startswith(("0.", "255."))})[:100]
    versions = sorted({m.group(1) for m in _VERSION.finditer(blob)})[:50]
    cred_markers = Counter(m.group(1).lower() for m in _CRED.finditer(blob))
    overall = round(shannon(data[:8 * 1024 * 1024]), 3)
    info = {"size_bytes": len(data), "entropy_overall": overall, "entropy_blocks_64k": prof,
            "entropy_note": "values near 8.0 suggest compressed or encrypted regions; this is a heuristic",
            "signatures": sigs[:100], "strings_extracted": len(strings), "urls": urls, "emails": emails,
            "ipv4_addresses": ips, "software_versions": versions,
            "credential_like_markers": dict(cred_markers),
            "credential_note": "marker words only; values are intentionally NOT recorded",
            "static_analysis_only": "the artifact was measured, never executed, emulated or unpacked"}
    p = ParsedIngest("firmware", "TECHINT", {"size": len(data), "signatures": len(sigs), "entropy": overall},
                     mime="application/octet-stream", access_class="OWNED_AUTHORIZED")
    p.observations.append(Obs("TECHINT", "firmware.static_analysis", info, confidence="medium"))
    for v in versions[:30]:
        p.entities.append(EntityDraft("component", v, v))
    if overall > 7.5:
        p.warnings.append("High overall entropy: contents are probably compressed or encrypted; string results are limited.")
    p.warnings.append("Analyse only firmware you own or are authorised to inspect.")
    return p


def _detect(name: str, head: bytes) -> str | None:
    if name.endswith((".cdx.json", ".bom.json", ".spdx.json", ".sbom.json")):
        return "sbom"
    if name.endswith((".bin", ".fw", ".img", ".rom", ".firmware")):
        return "firmware"
    return None


PARSERS["sbom"] = parse_cyclonedx
PARSERS["firmware"] = parse_firmware
DETECTORS.append(_detect)
