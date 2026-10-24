"""Document examination (PDF / DOCX) and SpiderFoot JSON import (spec 21.1 OSINT, Phase 3 importers).

Static, defensive inspection only. Nothing here renders, opens, executes, follows or fetches anything that a document
contains. PDFs are scanned at byte level for risky name tokens; DOCX files are opened as bounded ZIP archives and only
regular expressions touch their XML (no XML parser, so no entity-expansion surface). Every URL, address or macro flag is
a *claim made by the file* and is recorded as such.
"""
from __future__ import annotations

import io
import json
import re
import zipfile
import zlib
from collections import Counter
from urllib.parse import urlsplit

from .parsers import DETECTORS, PARSERS, EntityDraft, IngestError, Obs, ParsedIngest

MAX_URLS = 200
MAX_EMAILS = 100
MAX_ZIP_ENTRIES = 2000
MAX_ZIP_TOTAL = 64 * 1024 * 1024
MAX_STREAMS = 300
MAX_STREAM_OUT = 4 * 1024 * 1024
MAX_SF_EVENTS = 50_000

_URL = re.compile(rb"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{4,300}")
_EMAIL = re.compile(rb"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,200}\.[A-Za-z]{2,24}")
_RISKY_PDF = {
    "javascript": rb"/(?:JavaScript|JS)\b", "open_action": rb"/OpenAction\b", "additional_actions": rb"/AA\b",
    "launch": rb"/Launch\b", "embedded_file": rb"/EmbeddedFile\b", "acroform": rb"/AcroForm\b",
    "uri_action": rb"/URI\b", "submit_form": rb"/SubmitForm\b", "rich_media": rb"/RichMedia\b", "xfa": rb"/XFA\b",
}


def _clean(raw: bytes) -> str:
    return raw.decode("ascii", "replace").rstrip(".,);'\"")


def _extract(blob: bytes) -> tuple[list[str], list[str]]:
    urls = sorted({_clean(m) for m in _URL.findall(blob)})[:MAX_URLS]
    emails = sorted({m.decode("ascii", "replace").lower() for m in _EMAIL.findall(blob)})[:MAX_EMAILS]
    return urls, emails


def _add_entities(p: ParsedIngest, urls: list[str], emails: list[str]) -> None:
    seen: set[tuple[str, str]] = set()
    for u in urls:
        host = (urlsplit(u).hostname or "").lower()
        for t, k in (("url", u[:300]), ("domain", host)):
            if k and (t, k) not in seen:
                seen.add((t, k))
                p.entities.append(EntityDraft(t, k, k))
    for e in emails:
        if ("email", e) not in seen:
            seen.add(("email", e))
            p.entities.append(EntityDraft("email", e, e))


# --------------------------------------------------------------------------------------------------- PDF ---------
def _pdf_streams(data: bytes) -> bytes:
    """Decompress a bounded number of Flate streams so links inside them can be listed. Never interprets the content."""
    out, n, pos = [], 0, 0
    while n < MAX_STREAMS:
        i = data.find(b"stream", pos)
        if i < 0:
            break
        start = i + 6
        if data[start:start + 2] == b"\r\n":
            start += 2
        elif data[start:start + 1] in (b"\n", b"\r"):
            start += 1
        end = data.find(b"endstream", start)
        if end < 0:
            break
        pos = end + 9
        n += 1
        try:
            d = zlib.decompressobj()
            out.append(d.decompress(data[start:end], MAX_STREAM_OUT))
        except zlib.error:
            continue
    return b"\n".join(out)


def parse_pdf(data: bytes) -> ParsedIngest:
    if not data.lstrip()[:1024].startswith(b"%PDF-") and b"%PDF-" not in data[:1024]:
        raise IngestError("not a PDF (missing %PDF- header)")
    ver = re.search(rb"%PDF-(\d\.\d)", data[:1024])
    flags = {name: len(re.findall(rx, data)) for name, rx in _RISKY_PDF.items()}
    flags = {k: v for k, v in flags.items() if v}
    meta: dict[str, str] = {}
    for key in ("Title", "Author", "Creator", "Producer", "CreationDate", "ModDate", "Subject"):
        m = re.search(rb"/" + key.encode() + rb"\s*\(([^)]{0,200})\)", data)
        if m:
            meta[key.lower()] = m.group(1).decode("latin-1", "replace")
    pages = len(re.findall(rb"/Type\s*/Page\b", data))
    encrypted = b"/Encrypt" in data
    urls, emails = _extract(data + b"\n" + _pdf_streams(data))
    active = [k for k in flags if k in ("javascript", "open_action", "launch", "additional_actions", "rich_media", "xfa")]
    p = ParsedIngest("pdf", "OSINT", {"pages": pages, "active_content": bool(active), "urls": len(urls), "emails": len(emails)},
                     mime="application/pdf", access_class="IMPORTED", sensitivity="INTERNAL")
    p.observations.append(Obs("OSINT", "document.pdf", {
        "pdf_version": ver.group(1).decode() if ver else None, "pages_estimated": pages, "encrypted": encrypted,
        "metadata_claimed_by_file": meta, "risk_flags": flags, "active_content_present": bool(active), "urls": urls, "emails": emails,
        "note": "Metadata and links are claims made by the file. The document was scanned, not rendered or opened."}, confidence="low"))
    if active:
        p.warnings.append("This PDF contains active-content tokens (" + ", ".join(active) + "). Do not open it in a normal reader; use an isolated viewer.")
    if encrypted:
        p.warnings.append("The PDF is encrypted; text inside encrypted streams was not examined.")
    _add_entities(p, urls, emails)
    return p


# -------------------------------------------------------------------------------------------------- DOCX ---------
def parse_docx(data: bytes) -> ParsedIngest:
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise IngestError("not a valid ZIP/OOXML container") from exc
    infos = z.infolist()
    if len(infos) > MAX_ZIP_ENTRIES or sum(i.file_size for i in infos) > MAX_ZIP_TOTAL:
        raise IngestError("archive exceeds safety limits (entries or uncompressed size); refusing to expand it")
    names = [i.filename for i in infos]
    if any(n.startswith("/") or ".." in n.split("/") for n in names):
        raise IngestError("archive contains unsafe paths")
    if "word/document.xml" not in names:
        raise IngestError("not a Word (OOXML) document: word/document.xml is missing")

    def read(n: str, cap: int = 8 * 1024 * 1024) -> bytes:
        with z.open(n) as f:
            return f.read(cap)

    body = read("word/document.xml")
    text_runs = re.findall(rb"<w:t[^>]*>([^<]{0,2000})</w:t>", body)
    text = b" ".join(text_runs)
    macros = [n for n in names if n.lower().endswith("vbaproject.bin") or "/vba" in n.lower()]
    embedded = [n for n in names if n.startswith(("word/embeddings/", "word/activeX/"))]
    ext_targets: list[str] = []
    for n in names:
        if n.endswith(".rels"):
            for m in re.finditer(rb'Target="([^"]{1,400})"[^>]*TargetMode="External"', read(n, 1024 * 1024)):
                ext_targets.append(m.group(1).decode("utf8", "replace"))
    core: dict[str, str] = {}
    if "docProps/core.xml" in names:
        c = read("docProps/core.xml", 256 * 1024)
        for tag in ("dc:creator", "cp:lastModifiedBy", "dcterms:created", "dcterms:modified", "dc:title", "cp:revision"):
            mc = re.search(rb"<" + tag.encode() + rb"[^>]*>([^<]{0,200})</", c)
            if mc:
                core[tag.split(":")[1]] = mc.group(1).decode("utf8", "replace")
    app: dict[str, str] = {}
    if "docProps/app.xml" in names:
        a = read("docProps/app.xml", 256 * 1024)
        for tag in ("Application", "Company", "AppVersion", "Template"):
            ma = re.search(rb"<" + tag.encode() + rb"[^>]*>([^<]{0,200})</", a)
            if ma:
                app[tag.lower()] = ma.group(1).decode("utf8", "replace")
    urls, emails = _extract(text + b"\n" + "\n".join(ext_targets).encode())
    flags = {"macros": bool(macros), "embedded_objects": len(embedded),
             "external_relationships": len(ext_targets), "tracked_changes": b"<w:ins " in body or b"<w:del " in body,
             "comments": "word/comments.xml" in names}
    p = ParsedIngest("docx", "OSINT", {"paragraph_runs": len(text_runs), "macros": flags["macros"], "urls": len(urls), "emails": len(emails)},
                     mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document", access_class="IMPORTED")
    p.observations.append(Obs("OSINT", "document.docx", {
        "metadata_claimed_by_file": core, "application_claimed_by_file": app, "risk_flags": flags, "macro_parts": macros[:20],
        "embedded_parts": embedded[:50], "external_targets": ext_targets[:100], "urls": urls, "emails": emails,
        "text_preview": text[:600].decode("utf8", "replace"),
        "note": "Author, dates and application are claims in the file and are easily edited. The document was not opened or executed."}, confidence="low"))
    if flags["macros"]:
        p.warnings.append("The document contains VBA macro parts. It was NOT executed; treat it as potentially hostile.")
    if ext_targets:
        p.warnings.append(f"{len(ext_targets)} external relationship target(s) are listed; none were fetched.")
    _add_entities(p, urls, emails)
    return p


# ---------------------------------------------------------------------------------------------- SpiderFoot --------
_SF_TYPES = {
    "INTERNET_NAME": "domain", "DOMAIN_NAME": "domain", "AFFILIATE_INTERNET_NAME": "domain", "CO_HOSTED_SITE_DOMAIN": "domain",
    "IP_ADDRESS": "ip", "AFFILIATE_IPADDR": "ip", "EMAILADDR": "email", "EMAILADDR_GENERIC": "email",
    "USERNAME": "username", "LINKED_URL_INTERNAL": "url", "LINKED_URL_EXTERNAL": "url",
}


def parse_spiderfoot(data: bytes) -> ParsedIngest:
    try:
        rows = json.loads(data)
    except ValueError as exc:
        raise IngestError("not valid JSON") from exc
    if isinstance(rows, dict):
        rows = rows.get("events") or rows.get("data") or []
    if not isinstance(rows, list) or not rows or not all(isinstance(r, dict) for r in rows[:50]):
        raise IngestError("not a SpiderFoot JSON export (expected a list of event objects)")
    rows = rows[:MAX_SF_EVENTS]
    types: Counter[str] = Counter()
    modules: Counter[str] = Counter()
    samples: dict[str, list[str]] = {}
    seen: set[tuple[str, str]] = set()
    p = ParsedIngest("spiderfoot", "OSINT", {}, mime="application/json", access_class="IMPORTED")
    skipped = 0
    for r in rows:
        t = str(r.get("type") or r.get("event_type") or "").upper()
        val = str(r.get("data") if r.get("data") is not None else r.get("value", ""))[:300]
        if not t or not val:
            skipped += 1
            continue
        if r.get("false_positive") in (True, 1, "1"):
            skipped += 1
            continue
        types[t] += 1
        modules[str(r.get("module", "unknown"))[:60]] += 1
        s = samples.setdefault(t, [])
        if len(s) < 5:
            s.append(val)
        et = _SF_TYPES.get(t)
        if et and (et, val.lower()) not in seen and len(p.entities) < 5000:
            key = val.lower() if et != "url" else val
            if et == "email" and "@" not in val:
                continue
            seen.add((et, val.lower()))
            p.entities.append(EntityDraft(et, key, key))
    if not types:
        raise IngestError("no usable SpiderFoot events found")
    p.summary = {"events": sum(types.values()), "event_types": len(types), "entities": len(p.entities), "skipped": skipped}
    p.observations.append(Obs("OSINT", "spiderfoot.export", {
        "event_type_counts": dict(types.most_common(60)), "module_counts": dict(modules.most_common(40)), "samples": samples,
        "note": "Third-party module output. Each item is an unverified lead until independently corroborated and cited."}, confidence="low"))
    p.warnings.append("SpiderFoot results are leads, not findings: modules may have contacted third parties and results are not independently verified.")
    return p


def _detect(name: str, head: bytes) -> str | None:
    if name.endswith(".pdf") or head[:5] == b"%PDF-":
        return "pdf"
    if name.endswith((".docx", ".docm", ".dotx")):
        return "docx"
    if name.endswith((".spiderfoot.json", ".sf.json")):
        return "spiderfoot"
    return None


PARSERS["pdf"] = parse_pdf
PARSERS["docx"] = parse_docx
PARSERS["spiderfoot"] = parse_spiderfoot
DETECTORS.append(_detect)


