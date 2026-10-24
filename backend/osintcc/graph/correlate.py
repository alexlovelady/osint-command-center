"""Cross-discipline correlation suggestions and a unified timeline (spec 21.7 P5B, 23.5).

Rules: a suggestion is only a coincidence in time and/or place between observations from DIFFERENT disciplines. It never
becomes a relationship until an analyst accepts it, accepted/rejected decisions are reversible and visible, and where
accuracy is unknown that is said rather than assumed. Source quality is shown as an ordinal hint, never as a score.
"""
from __future__ import annotations

import hashlib
import math
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db.models import CaptureSession, Correlation, Finding, Observation

MAX_OBS = 5000
CAVEAT = "Coincidence in time or place is not a relationship. Each side must be inspected and accepted by an analyst."
QUALITY_HINT = {"OWNED_AUTHORIZED": "high: collected under your control", "CONSENTED": "medium: a consenting person's account",
                "PUBLIC": "medium: public broadcast/record, provider-dependent", "IMPORTED": "medium: supplied file, provenance partly unknown",
                "SIMULATION": "none: simulated data", "UNSUPPORTED": "unknown"}


def _aware(d: datetime | None) -> datetime | None:
    return d.replace(tzinfo=UTC) if d is not None and d.tzinfo is None else d


def haversine_m(a: tuple[float, float], b: tuple[float, float]) -> float:
    (la1, lo1), (la2, lo2) = a, b
    p1, p2 = math.radians(la1), math.radians(la2)
    dphi, dl = p2 - p1, math.radians(lo2 - lo1)
    h = math.sin(dphi / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * 6371008.8 * math.asin(math.sqrt(h))


def _loc(o: Observation) -> tuple[float, float, float | None] | None:
    loc = (o.data_json or {}).get("location")
    if isinstance(loc, dict) and isinstance(loc.get("lat"), (int, float)) and isinstance(loc.get("lon"), (int, float)):
        return float(loc["lat"]), float(loc["lon"]), loc.get("accuracy_m")
    return None


def pair_key(a: str, b: str, kind: str) -> tuple[str, str, str]:
    x, y = sorted([a, b])
    return x, y, kind


def _side(o: Observation) -> dict[str, Any]:
    return {"id": o.id, "discipline": o.discipline_id, "kind": o.kind, "observed_at": _aware(o.observed_at), "evidence_id": o.raw_evidence_id,
            "access_class": o.access_class, "quality_hint": QUALITY_HINT.get(o.access_class, "unknown"), "sensitivity": o.sensitivity}


def suggest(db: Session, case_id: str, window_s: float = 300.0, radius_m: float = 1000.0, include_restricted: bool = False) -> dict[str, Any]:
    obs = [o for o in db.scalars(select(Observation).where(Observation.case_id == case_id).limit(MAX_OBS))
           if include_restricted or o.sensitivity not in ("RESTRICTED", "SECRET")]
    decided = {(c.obs_a_id, c.obs_b_id, c.kind): c for c in db.scalars(select(Correlation).where(Correlation.case_id == case_id))}
    out: dict[tuple[str, str, str], dict[str, Any]] = {}

    timed = sorted([o for o in obs if o.observed_at is not None], key=lambda o: _aware(o.observed_at))  # type: ignore[arg-type,return-value]
    j0 = 0
    for i, a in enumerate(timed):
        ta = _aware(a.observed_at)
        assert ta is not None
        while j0 < i and (ta - _aware(timed[j0].observed_at)).total_seconds() > window_s:  # type: ignore[operator]
            j0 += 1
        for b in timed[j0:i]:
            if a.discipline_id == b.discipline_id or a.raw_evidence_id == b.raw_evidence_id:
                continue
            dt = (ta - _aware(b.observed_at)).total_seconds()  # type: ignore[operator]
            out[pair_key(a.id, b.id, "temporal")] = {"type": "temporal", "a": _side(b), "b": _side(a), "delta_s": dt, "distance_m": None, "warnings": []}
    located = [(o, _loc(o)) for o in obs if _loc(o)]
    for i, (a, la) in enumerate(located):
        for b, lb in located[:i]:
            if a.discipline_id == b.discipline_id or a.raw_evidence_id == b.raw_evidence_id or la is None or lb is None:
                continue
            d = haversine_m((la[0], la[1]), (lb[0], lb[1]))
            warn = []
            slack = 0.0
            if la[2] is None or lb[2] is None:
                warn.append("accuracy unknown for at least one position; distance is a nominal value only")
            else:
                slack = float(la[2]) + float(lb[2])
            if d <= radius_m + slack:
                out[pair_key(a.id, b.id, "spatial")] = {"type": "spatial", "a": _side(b), "b": _side(a), "delta_s": None, "distance_m": d,
                                                        "warnings": warn}
    # a pair that matches both ways is reported as 'both'
    both: dict[tuple[str, str, str], dict[str, Any]] = {}
    for (x, y, kind), v in list(out.items()):
        if kind == "temporal" and (x, y, "spatial") in out:
            s = out[(x, y, "spatial")]
            both[(x, y, "both")] = {**v, "type": "both", "distance_m": s["distance_m"], "warnings": s["warnings"]}
            del out[(x, y, "temporal")]
            del out[(x, y, "spatial")]
    out.update(both)
    items = []
    for k, v in out.items():
        dec = decided.get(k)
        if dec and dec.status == "rejected":
            continue
        items.append({**v, "key": hashlib.sha256("|".join(k).encode()).hexdigest()[:16], "status": dec.status if dec else "suggested",
                      "correlation_id": dec.id if dec else None, "note": dec.note if dec else ""})
    items.sort(key=lambda x: (x["status"] != "suggested", abs(x["delta_s"] or 0)))
    return {"items": items[:500], "total": len(items), "window_s": window_s, "radius_m": radius_m, "caveat": CAVEAT,
            "truncated": len(items) > 500 or len(obs) >= MAX_OBS}


def unified_timeline(db: Session, case_id: str, start: datetime | None, end: datetime | None, discipline: str | None,
                     limit: int = 500, include_restricted: bool = False) -> list[dict[str, Any]]:
    """Observations, findings and capture sessions on one axis. Each row says which of its times it is using."""
    rows: list[dict[str, Any]] = []
    for o in db.scalars(select(Observation).where(Observation.case_id == case_id)):
        if not include_restricted and o.sensitivity in ("RESTRICTED", "SECRET"):
            continue
        t, basis = (_aware(o.observed_at), "observed") if o.observed_at else (_aware(o.ingested_at), "ingested (event time unknown)")
        rows.append({"source": "observation", "id": o.id, "time": t, "time_basis": basis, "discipline": o.discipline_id, "label": o.kind,
                     "evidence_id": o.raw_evidence_id, "access_class": o.access_class, "located": _loc(o) is not None})
    for f in db.scalars(select(Finding).where(Finding.case_id == case_id)):
        t, basis = (_aware(f.source_published_at), "published by source") if f.source_published_at else (_aware(f.observed_at), "captured by this app")
        rows.append({"source": "finding", "id": f.id, "time": t, "time_basis": basis, "discipline": "OSINT", "label": f.predicate,
                     "evidence_id": f.evidence_id, "access_class": "PUBLIC", "located": False})
    for c in db.scalars(select(CaptureSession).where(CaptureSession.case_id == case_id)):
        rows.append({"source": "capture", "id": c.id, "time": _aware(c.started_at), "time_basis": "session start", "discipline": "SIGINT",
                     "label": f"capture {c.status}", "evidence_id": c.artifact_id, "access_class": "SIMULATION", "located": False})
    if discipline:
        rows = [r for r in rows if r["discipline"] == discipline]
    if start:
        rows = [r for r in rows if r["time"] and r["time"] >= start]
    if end:
        rows = [r for r in rows if r["time"] and r["time"] <= end]
    rows.sort(key=lambda r: r["time"] or datetime.min.replace(tzinfo=UTC))
    return rows[:limit]
