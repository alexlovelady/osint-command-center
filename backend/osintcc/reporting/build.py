"""Report generation: HTML / Markdown / JSON / PDF with evidence manifest and limitations (spec 13)."""
from __future__ import annotations

import hashlib
import html
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import nh3
from markdown_it import MarkdownIt
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db.models import (
    Case,
    Entity,
    Evidence,
    Finding,
    Note,
    Observation,
    Relationship,
    RelationshipEvidence,
    Requirement,
)

DISCLAIMER = ("Findings come from public sources and were accurate only as of their retrieval time. Matching "
              "identifiers, usernames or names are leads, not proof of identity or common ownership. Graph edges "
              "state what a source asserted; they are not independently verified real-world relationships. "
              "Absence of a record is not proof of non-existence.")
PROFILES = ("executive", "technical", "evidence_pack", "multi_int")
_md = MarkdownIt("commonmark", {"html": False})


def _iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    return (dt if dt.tzinfo else dt.replace(tzinfo=UTC)).isoformat()


def render_markdown_safe(md: str) -> str:
    return nh3.clean(_md.render(md), tags={"p", "em", "strong", "ul", "ol", "li", "code", "pre", "blockquote", "br",
                                           "h1", "h2", "h3", "h4", "a"}, attributes={"a": {"href"}},
                     url_schemes={"http", "https", "mailto"})


def _round_loc(loc: dict | None) -> dict | None:
    if not loc:
        return None
    return {"lat": round(loc["lat"], 2), "lon": round(loc["lon"], 2), "crs": loc.get("crs"),
            "precision": "rounded to 0.01 degrees (about 1 km) in this export; exact value withheld"}


def _obs_rows(db: Session, case_id: str, redact_sensitive: bool) -> list[dict[str, Any]]:
    rows = []
    for o in db.scalars(select(Observation).where(Observation.case_id == case_id).order_by(Observation.observed_at)):
        if redact_sensitive and o.sensitivity in ("RESTRICTED", "SECRET"):
            continue
        data = dict(o.data_json or {})
        if "location" in data:
            data["location"] = (data["location"] if not redact_sensitive else _round_loc(data["location"]))
        brief = {k: v for k, v in data.items() if not isinstance(v, (list, dict)) or k == "location"}
        rows.append({"id": o.id, "discipline": o.discipline_id, "kind": o.kind, "access_class": o.access_class,
                     "observed_at": _iso(o.observed_at), "ingested_at": _iso(o.ingested_at), "summary": brief,
                     "evidence_id": o.raw_evidence_id, "confidence": o.confidence, "review_status": o.review_status})
    return rows


def _collect_base(db: Session, case_id: str, profile: str = "technical", redact_sensitive: bool = True) -> dict[str, Any]:
    case = db.get(Case, case_id)
    if case is None:
        raise ValueError("case not found")
    ents = {e.id: e for e in db.scalars(select(Entity).where(Entity.case_id == case_id))}
    evs = {e.id: e for e in db.scalars(select(Evidence).where(Evidence.case_id == case_id))}
    findings = db.scalars(select(Finding).where(Finding.case_id == case_id).order_by(Finding.observed_at)).all()
    rows = []
    for f in findings:
        ev = evs.get(f.evidence_id)
        rows.append({"id": f.id, "subject": ents[f.subject_entity_id].display_name,
                     "subject_type": ents[f.subject_entity_id].type, "predicate": f.predicate,
                     "value": f.value_json, "confidence": f.confidence, "confidence_reason": f.confidence_reason,
                     "status": f.status, "adapter": f"{f.adapter_id}@{f.adapter_version}",
                     "evidence_id": f.evidence_id, "source_url": ev.original_url if ev else None,
                     "observed_at": _iso(f.observed_at), "source_published_at": _iso(f.source_published_at)})
    rels = []
    for r in db.scalars(select(Relationship).where(Relationship.case_id == case_id, Relationship.status != "rejected")):
        eids = [x.evidence_id for x in db.scalars(select(RelationshipEvidence)
                                                   .where(RelationshipEvidence.relationship_id == r.id))]
        rels.append({"from": ents[r.from_entity_id].display_name, "to": ents[r.to_entity_id].display_name,
                     "type": r.relation_type, "status": r.status, "confidence": r.confidence,
                     "confidence_reason": r.confidence_reason, "evidence_ids": eids})
    notes = [{"id": n.id, "created_at": _iso(n.created_at), "html": render_markdown_safe(n.body_markdown),
              "markdown": n.body_markdown} for n in db.scalars(select(Note).where(Note.case_id == case_id))]
    manifest = [{"evidence_id": e.id, "title": e.title, "sha256": e.sha256, "bytes": e.byte_size,
                 "source_url": e.original_url, "retrieved_at": _iso(e.retrieved_at), "kind": e.kind,
                 "sensitivity": e.sensitivity, "redacted": e.redacted}
                for e in sorted(evs.values(), key=lambda x: x.created_at)]
    if redact_sensitive:
        hidden = {e["evidence_id"] for e in manifest if e["sensitivity"] in ("RESTRICTED", "SECRET")}
        manifest = [m for m in manifest if m["evidence_id"] not in hidden]
        rows = [r for r in rows if r["evidence_id"] not in hidden]
    reqs = [{"question": q.question, "priority": q.priority, "status": q.status}
            for q in db.scalars(select(Requirement).where(Requirement.case_id == case_id))]
    manifest_sha = hashlib.sha256(json.dumps(manifest, sort_keys=True).encode()).hexdigest()
    counts: dict[str, int] = {}
    for row in rows:
        counts[row["confidence"]] = counts.get(row["confidence"], 0) + 1
    obs_rows = _obs_rows(db, case_id, redact_sensitive)
    return {"profile": profile, "generated_at": datetime.now(UTC).isoformat(),
            "case": {"id": case.id, "title": case.title, "category": case.category, "purpose": case.purpose,
                     "status": case.status, "scope": case.scope_json},
            "summary": {"findings": len(rows), "relationships": len(rels), "evidence_items": len(manifest),
                        "observations": len(obs_rows),
                        "confidence_counts": counts, "entities": len(ents)},
            "observations": obs_rows,
            "requirements": reqs, "findings": rows, "relationships": rels, "notes": notes, "evidence_manifest": manifest,
            "evidence_manifest_sha256": manifest_sha, "limitations": DISCLAIMER,
            "redaction": "RESTRICTED/SECRET evidence excluded" if redact_sensitive else "none"}


def _cell(v: Any) -> str:
    return html.escape(json.dumps(v) if not isinstance(v, str) else v)


def to_html(d: dict[str, Any]) -> str:
    c, s = d["case"], d["summary"]
    e = html.escape
    parts = [f"<!doctype html><html lang='en'><head><meta charset='utf-8'><title>{e(c['title'])}</title>"
             "<style>body{font:15px/1.5 system-ui,sans-serif;max-width:1000px;margin:2rem auto;padding:0 1rem;color:#14202b}"
             "table{border-collapse:collapse;width:100%;font-size:13px}td,th{border:1px solid #c9d3dc;padding:4px 6px;"
             "vertical-align:top;text-align:left}th{background:#e9f0f5}.warn{background:#fff6e0;border:1px solid #e2c36b;"
             "padding:.6rem}code{word-break:break-all}</style></head><body>",
             f"<h1>{e(c['title'])}</h1><p>Profile: <b>{e(d['profile'])}</b> · generated {e(d['generated_at'])} · "
             f"case status {e(c['status'])}</p>",
             f"<p><b>Purpose:</b> {e(c['purpose'] or 'not stated')}</p>",
             f"<div class='warn'><b>Limitations.</b> {e(d['limitations'])}</div>",
             f"<h2>Summary</h2><p>{s['findings']} findings, {s['relationships']} relationships, "
             f"{s['evidence_items']} evidence items. Confidence labels: {e(json.dumps(s['confidence_counts']))}.</p>"]
    if d["requirements"]:
        parts.append("<h2>Intelligence requirements</h2><ul>" + "".join(
            f"<li>[{e(r['status'])}] {e(r['question'])} ({e(r['priority'])})</li>" for r in d["requirements"]) + "</ul>")
    if d["profile"] != "evidence_pack" or True:
        parts.append("<h2>Findings</h2><table><tr><th>Subject</th><th>Predicate</th><th>Value</th><th>Confidence</th>"
                     "<th>Observed (UTC)</th><th>Source published</th><th>Source</th><th>Evidence</th></tr>")
        limit = 25 if d["profile"] == "executive" else None
        for r in d["findings"][:limit]:
            src = f"<a href='{e(r['source_url'])}'>{e(r['source_url'])}</a>" if (r["source_url"] or "").startswith(
                "http") else e(r["source_url"] or "")
            parts.append(f"<tr><td>{e(r['subject'])}</td><td>{e(r['predicate'])}</td><td>{_cell(r['value'])}</td>"
                         f"<td>{e(r['confidence'])}<br><small>{e(r['confidence_reason'])}</small></td>"
                         f"<td>{e(r['observed_at'] or 'unknown')}</td><td>{e(r['source_published_at'] or 'unknown')}</td>"
                         f"<td>{src}<br><small>{e(r['adapter'])}</small></td><td><code>{e(r['evidence_id'])}</code></td></tr>")
        parts.append("</table>")
    if d["profile"] != "executive":
        parts.append("<h2>Relationships (source assertions)</h2><table><tr><th>From</th><th>Relation</th><th>To</th>"
                     "<th>Status</th><th>Evidence</th></tr>")
        for r in d["relationships"]:
            parts.append(f"<tr><td>{e(r['from'])}</td><td>{e(r['type'])}</td><td>{e(r['to'])}</td>"
                         f"<td>{e(r['status'])} / {e(r['confidence'])}</td><td>{e(', '.join(r['evidence_ids']))}</td></tr>")
        parts.append("</table>")
    if d.get("claims"):
        parts.append("<h2>Claims</h2><p>Labels are heuristics from independent source groups, not probabilities.</p><table><tr><th>Statement</th><th>Confidence</th>"
                     "<th>Verification</th><th>Independent groups</th><th>Evidence</th></tr>")
        for c in d["claims"]:
            parts.append(f"<tr><td>{e(c['statement'])}</td><td>{e(c['confidence'])}</td><td>{e(c['verification'])}</td>"
                         f"<td>{c['independent_source_groups']}</td><td><code>{e(', '.join(c['evidence_ids']))}</code></td></tr>")
        parts.append("</table>")
    if d.get("contradictions"):
        parts.append("<h2>Contradictions (all positions preserved)</h2>")
        for g in d["contradictions"]:
            parts.append(f"<p><b>{e(g['subject'])}</b> {e(g['predicate'])}: " + " | ".join(
                f"{e(str(p['value']))} [{e(p['confidence'])}, {e(p['verification'])}]" for p in g["positions"]) + "</p>")
    if d.get("hypotheses") and d["profile"] in ("executive", "multi_int", "technical"):
        parts.append("<h2>Alternative explanations considered</h2><ul>" + "".join(
            f"<li>{e(h['statement'])} - <b>{e(h['status'])}</b> (supports {h['tally']['support']}, contradicts {h['tally']['contradict']}; a tally, not a probability)</li>"
            for h in d["hypotheses"]) + "</ul>")
    if d.get("gaps") and d["profile"] != "evidence_pack":
        g = d["gaps"]
        parts.append(f"<h2>Gaps and limits</h2><p>{e(g['summary'])}</p>" + ("<ul>" + "".join(f"<li>Unanswered: {e(q)}</li>" for q in g["unanswered_requirements"]) + "</ul>" if g["unanswered_requirements"] else ""))
    if d["profile"] == "multi_int" and d.get("annexes"):
        parts.append("<h2>Discipline annexes</h2>")
        for disc, a in sorted(d["annexes"].items()):
            parts.append(f"<h3>{e(disc)}</h3><p>{a['observations']} observation(s); kinds: {e(json.dumps(a['kinds']))}; access classes: {e(json.dumps(a['access_classes']))}</p>"
                         f"<p><i>Caveat:</i> {e(a['caveat'])}</p>")
        m = d["methodology"]
        parts.append(f"<h3>Methodology</h3><p>Capture methods: {e(', '.join(m['capture_methods']))}</p><p>{e(d['chain_of_custody']['note'])} "
                     f"({d['chain_of_custody']['with_custody_events']}/{d['chain_of_custody']['evidence_items']} items carry custody events)</p>")
    if d.get("observations"):
        parts.append("<h2>Imported observations</h2><p class='muted'>Facts extracted by parsers from supplied files; "
                     "not conclusions. Exact private coordinates are rounded unless a sensitive export was requested.</p>"
                     "<table><tr><th>Discipline</th><th>Kind</th><th>Observed</th><th>Summary</th><th>Evidence</th></tr>")
        for o in d["observations"]:
            parts.append(f"<tr><td>{e(o['discipline'])}<br><small>{e(o['access_class'])}</small></td><td>{e(o['kind'])}</td>"
                         f"<td>{e(o['observed_at'] or 'unknown')}</td><td>{_cell(o['summary'])}</td>"
                         f"<td><code>{e(o['evidence_id'])}</code></td></tr>")
        parts.append("</table>")
    if d["notes"]:
        parts.append("<h2>Analyst notes</h2>" + "".join(
            f"<div><small>{e(n['created_at'] or '')}</small>{n['html']}</div>" for n in d["notes"]))
    parts.append(f"<h2>Evidence manifest</h2><p>Manifest SHA-256: <code>{d['evidence_manifest_sha256']}</code> · "
                 f"redaction: {e(d['redaction'])}</p><table><tr><th>Evidence</th><th>Title</th><th>SHA-256</th>"
                 "<th>Bytes</th><th>Retrieved</th></tr>")
    for m in d["evidence_manifest"]:
        parts.append(f"<tr><td><code>{e(m['evidence_id'])}</code></td><td>{e(m['title'])}</td>"
                     f"<td><code>{m['sha256']}</code></td><td>{m['bytes']}</td><td>{e(m['retrieved_at'] or '')}</td></tr>")
    parts.append("</table></body></html>")
    return "".join(parts)


def to_markdown(d: dict[str, Any]) -> str:
    c, s = d["case"], d["summary"]
    out = [f"# {c['title']}", "", f"Profile: {d['profile']} · generated {d['generated_at']}", "",
           f"**Purpose:** {c['purpose'] or 'not stated'}", "", f"> **Limitations.** {d['limitations']}", "",
           "## Summary", "", f"{s['findings']} findings, {s['relationships']} relationships, "
           f"{s['evidence_items']} evidence items.", "", "## Findings", "",
           "| Subject | Predicate | Value | Confidence | Observed (UTC) | Evidence |", "|---|---|---|---|---|---|"]
    for r in d["findings"]:
        v = str(r["value"]).replace("|", "\\|").replace("\n", " ")
        out.append(f"| {r['subject']} | {r['predicate']} | {v} | {r['confidence']} | {r['observed_at']} | "
                   f"{r['evidence_id']} |")
    if d.get("claims"):
        out += ["", "## Claims", "", "| Statement | Confidence | Verification | Independent groups |", "|---|---|---|---|"]
        out += [f"| {c['statement']} | {c['confidence']} | {c['verification']} | {c['independent_source_groups']} |" for c in d["claims"]]
    if d.get("contradictions"):
        out += ["", "## Contradictions (all positions preserved)", ""]
        out += [f"- **{g['subject']}** {g['predicate']}: " + " | ".join(f"{p['value']} [{p['confidence']}, {p['verification']}]" for p in g["positions"]) for g in d["contradictions"]]
    if d.get("hypotheses"):
        out += ["", "## Alternative explanations considered", ""]
        out += [f"- {h['statement']} - **{h['status']}** (supports {h['tally']['support']}, contradicts {h['tally']['contradict']}; a tally, not a probability)" for h in d["hypotheses"]]
    if d.get("gaps"):
        out += ["", "## Gaps and limits", "", d["gaps"]["summary"]]
    if d["profile"] == "multi_int" and d.get("annexes"):
        out += ["", "## Discipline annexes", ""]
        for disc, a in sorted(d["annexes"].items()):
            out += [f"### {disc}", f"{a['observations']} observation(s); kinds {json.dumps(a['kinds'])}.", f"*Caveat:* {a['caveat']}", ""]
    if d.get("observations"):
        out += ["", "## Imported observations", "", "| Discipline | Kind | Observed | Evidence |", "|---|---|---|---|"]
        out += [f"| {o['discipline']} | {o['kind']} | {o['observed_at']} | {o['evidence_id']} |" for o in d["observations"]]
    out += ["", "## Evidence manifest", "", f"Manifest SHA-256: `{d['evidence_manifest_sha256']}`", ""]
    out += [f"- `{m['evidence_id']}` {m['title']} — `{m['sha256']}` ({m['bytes']} bytes)" for m in d["evidence_manifest"]]
    return "\n".join(out) + "\n"


def to_pdf(d: dict[str, Any], path: Path) -> None:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    ss = getSampleStyleSheet()
    small = ss["BodyText"].clone("small", fontSize=7, leading=9)
    doc = SimpleDocTemplate(str(path), pagesize=A4, title=d["case"]["title"], author="OSINT Command Center",
                            invariant=True)  # invariant => reproducible bytes for identical input
    story = [Paragraph(html.escape(d["case"]["title"]), ss["Title"]),
             Paragraph(f"Profile: {d['profile']} — generated {d['generated_at']}", ss["BodyText"]),
             Paragraph(f"<b>Limitations.</b> {html.escape(d['limitations'])}", ss["BodyText"]), Spacer(1, 8),
             Paragraph("Findings", ss["Heading2"])]
    data = [["Subject", "Predicate", "Value", "Conf.", "Evidence"]]
    for r in d["findings"]:
        data.append([Paragraph(html.escape(str(x)[:160]), small) for x in
                     (r["subject"], r["predicate"], r["value"], r["confidence"], r["evidence_id"][:8])])
    t = Table(data, repeatRows=1, colWidths=[90, 90, 190, 40, 50])
    t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                           ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e9f0f5"))]))
    story += [t, Spacer(1, 8), Paragraph("Evidence manifest", ss["Heading2"]),
              Paragraph(f"SHA-256: {d['evidence_manifest_sha256']}", small)]
    for m in d["evidence_manifest"]:
        story.append(Paragraph(html.escape(f"{m['evidence_id'][:8]} {m['title']} {m['sha256']}"), small))
    doc.build(story)


def write_report(d: dict[str, Any], fmt: str, out_dir: Path, stem: str) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    p = out_dir / f"{stem}.{ {'markdown': 'md'}.get(fmt, fmt) }"
    if fmt == "html":
        p.write_text(to_html(d), encoding="utf-8")
    elif fmt == "markdown":
        p.write_text(to_markdown(d), encoding="utf-8")
    elif fmt == "json":
        p.write_text(json.dumps(d, indent=2, sort_keys=True), encoding="utf-8")
    elif fmt == "pdf":
        to_pdf(d, p)
    else:
        raise ValueError("unsupported format")
    return p


DISCIPLINE_CAVEATS = {
    "OSINT": "Public sources reflect what was published at retrieval time; they can be wrong, stale or manipulated.",
    "COMINT": "Message headers and bodies are claims by the message; no authentication (DKIM/SPF) is performed. Nothing here was intercepted.",
    "SIGINT": "Spectral findings describe a supplied recording only; transmitter identity and location are not inferred.",
    "ELINT": "Pulse statistics are descriptors of synthetic or owner-lab data; no emitter identification is made.",
    "FISINT": "Telemetry is interpreted only through primary headers or supplied calibration; payload meaning is not asserted.",
    "HUMINT": "Statements are uncorroborated until independent sources agree; reliability grades are an analyst's judgement.",
    "GEOINT": "Positions come from files that can be edited; accuracy is stated only where the file states it. Pixel differences are not verified events.",
    "MASINT": "Anomaly intervals are statistical outliers; their physical cause is unknown.",
    "CYBINT": "Network data shows what a capture contained; endpoints are not attributed to people or organisations.",
    "FININT": "Filings are matched by official identifier; blockchain addresses are pseudonymous and sanctions hits are name-similarity leads only.",
    "TECHINT": "Static inspection only: artifacts were measured, never executed; SBOMs are supplier declarations.",
}


def _extras(db: Session, case_id: str, redact: bool) -> dict[str, Any]:
    from ..db.models import Claim, Hypothesis, HypothesisClaim, Source
    from ..graph import fusion
    hidden = {e.id for e in db.scalars(select(Evidence).where(Evidence.case_id == case_id, Evidence.sensitivity.in_(("RESTRICTED", "SECRET"))))} if redact else set()
    claims = []
    for c in db.scalars(select(Claim).where(Claim.case_id == case_id, Claim.verification_status != "rejected")):
        d = fusion.claim_dict(db, c)
        if hidden and any(x["evidence_id"] in hidden for x in d["sources"]):
            continue
        claims.append({"statement": f"{d['subject']} {d['predicate']} {d['value'] if d['value'] is not None else d['object']}",
                       "confidence": d["confidence_label"], "verification": d["verification_status"],
                       "independent_source_groups": d["independent_source_groups"], "evidence_ids": [x["evidence_id"] for x in d["sources"]]})
    hyps = []
    for h in db.scalars(select(Hypothesis).where(Hypothesis.case_id == case_id)):
        tally = {"support": 0, "contradict": 0, "neutral": 0}
        for r in db.scalars(select(HypothesisClaim).where(HypothesisClaim.hypothesis_id == h.id)):
            tally[r.stance] += 1
        hyps.append({"statement": h.statement, "status": h.status, "tally": tally, "rationale": h.rationale})
    contra = []
    for g in fusion.contradictions(db, case_id):
        positions = [{"value": p["value"] if p["value"] is not None else p["object"], "confidence": p["confidence_label"],
                      "verification": p["verification_status"], "groups": p["independent_source_groups"]}
                     for p in g["positions"] if not (hidden and any(x["evidence_id"] in hidden for x in p["sources"]))]
        if len(positions) > 1:
            contra.append({"subject": g["subject"], "predicate": g["predicate"], "positions": positions})
    gaps = fusion.gap_assessment(db, case_id)
    obs = _obs_rows(db, case_id, redact)
    annexes: dict[str, dict[str, Any]] = {}
    for o in obs:
        a = annexes.setdefault(o["discipline"], {"observations": 0, "kinds": {}, "access_classes": {}, "caveat": DISCIPLINE_CAVEATS.get(o["discipline"], "")})
        a["observations"] += 1
        a["kinds"][o["kind"]] = a["kinds"].get(o["kind"], 0) + 1
        a["access_classes"][o["access_class"]] = a["access_classes"].get(o["access_class"], 0) + 1
    methods = sorted({(e.capture_method or "unknown") for e in db.scalars(select(Evidence).where(Evidence.case_id == case_id))
                      if e.id not in hidden})
    custody = {"evidence_items": 0, "with_custody_events": 0, "events": 0}
    for e in db.scalars(select(Evidence).where(Evidence.case_id == case_id)):
        if e.id in hidden:
            continue
        custody["evidence_items"] += 1
        n = len(e.chain_of_custody_json or [])
        custody["events"] += n
        custody["with_custody_events"] += 1 if n else 0
    sources = sorted({(s.adapter_id, (s.metadata_json or {}).get("adapter_version", "")) for s in db.scalars(select(Source))
                      if any(True for _ in [0])})  # adapter versions seen anywhere; used only for the methodology list
    return {"claims": claims, "hypotheses": hyps, "contradictions": contra, "gaps": {
                "summary": gaps["summary"], "unanswered_requirements": [r["question"] for r in gaps["unanswered_requirements"]],
                "stale_findings": gaps["stale_findings"], "unverified_claims": gaps["unverified_claims"], "disputed_claims": gaps["disputed_claims"]},
            "annexes": annexes, "methodology": {"capture_methods": methods, "adapter_versions": [f"{a}@{v}" if v else a for a, v in sources][:40]},
            "chain_of_custody": {**custody, "note": "Custody entries record capture/import/derivation by this application; they are not a legal chain-of-custody certificate."},
            "alternative_explanations": [h for h in hyps if h["status"] in ("open", "supported", "refuted")]}


def collect(db: Session, case_id: str, profile: str = "technical", redact_sensitive: bool = True) -> dict[str, Any]:
    data = _collect_base(db, case_id, profile, redact_sensitive)
    data.update(_extras(db, case_id, redact_sensitive))
    data["summary"]["claims"] = len(data["claims"])
    return data
