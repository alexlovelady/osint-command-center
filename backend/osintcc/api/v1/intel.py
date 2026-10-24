"""GEOINT/CYBINT/FININT endpoints that build on imported evidence (spec 21.6)."""
from __future__ import annotations

import asyncio
import hashlib
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import select

from ...db.models import (
    Entity,
    Evidence,
    GeospatialLayer,
    GraphProposal,
    Observation,
    Relationship,
    RelationshipEvidence,
)
from ...evidence.vault import VaultError
from ...ingest import fin, geo, net, parsers
from ...main import ApiError
from ...telemetry import audit
from .routes import S, actor, case_for

router: APIRouter = APIRouter()


def _read_evidence(st, db, case_id: str, evidence_id: str) -> tuple[Evidence, bytes]:
    ev = db.get(Evidence, evidence_id)
    if not ev or ev.case_id != case_id or not ev.vault_relpath:
        raise ApiError(404, "not_found", "evidence not found in this case")
    try:
        return ev, st.vault.read(ev.vault_relpath, ev.sha256)  # hash-verified
    except VaultError as exc:
        raise ApiError(409, "integrity_failure", str(exc)) from exc


# ---------------------------------------------------------------- geo ------------------------------------------------
class ChangeIn(BaseModel):
    before_evidence_id: str
    after_evidence_id: str
    threshold: int = Field(default=30, ge=1, le=255)


@router.post("/cases/{case_id}/geo/change", status_code=201)
async def geo_change(request: Request, case_id: str, body: ChangeIn):
    st = S(request)
    with st.sm() as db:
        case_for(db, request, case_id, "editor")
        eb, before = _read_evidence(st, db, case_id, body.before_evidence_id)
        ea, after = _read_evidence(st, db, case_id, body.after_evidence_id)
        try:
            res = await asyncio.to_thread(geo.change_detection, before, after, body.threshold)
        except parsers.IngestError as exc:
            raise ApiError(422, "malformed_input", str(exc)) from exc
        png = res.pop("_png")
        sha256, sha512, rel, size = st.vault.store(png)
        now = datetime.now(UTC)
        mask = Evidence(case_id=case_id, kind="geo.change_mask", title="change mask (derived)", sha256=sha256, sha512=sha512,
                        byte_size=size, mime_type="image/png", vault_relpath=rel, retrieved_at=now, observed_at=now,
                        capture_method="derived:geo.change_detection", created_by=actor(request),
                        description=f"derived from evidence {eb.id} and {ea.id}",
                        chain_of_custody_json=[{"event": "derived", "at": now.isoformat(), "inputs": [eb.id, ea.id],
                                                "sha256": sha256}])
        db.add(mask)
        db.flush()
        obs = Observation(case_id=case_id, discipline_id="GEOINT", kind="geo.change_detection", access_class="IMPORTED",
                          ingested_at=now, data_json=res, raw_evidence_id=mask.id, derived_from_json=[eb.id, ea.id],
                          confidence="low", parser_version=geo.PARSER_GEO)
        db.add(obs)
        audit.record(db, "geo.change", actor=actor(request), case_id=case_id, resource_id=obs.id)
        db.commit()
        return {"observation_id": obs.id, "mask_evidence_id": mask.id, "derived_from": [eb.id, ea.id], **res}


@router.get("/cases/{case_id}/geo/points")
async def geo_points(request: Request, case_id: str):
    """Points for the map. Each carries its accuracy statement; 'unknown' is shown, never invented."""
    with S(request).sm() as db:
        case_for(db, request, case_id)
        out = []
        for o in db.scalars(select(Observation).where(Observation.case_id == case_id,
                                                      Observation.kind == "geo.exif_position")):
            loc = (o.data_json or {}).get("location")
            if loc:
                out.append({"observation_id": o.id, "evidence_id": o.raw_evidence_id, "lat": loc["lat"], "lon": loc["lon"],
                            "crs": loc["crs"], "accuracy_m": loc.get("accuracy_m"), "accuracy_note": loc.get("accuracy_note"),
                            "observed_at": o.observed_at, "source": "EXIF GPS in a user-supplied image",
                            "sensitivity": o.sensitivity, "kind": "exif"})
        return {"items": out, "attribution": "Basemap © OpenStreetMap contributors (ODbL)",
                "warning": "EXIF coordinates are claims made by a file; IP-based locations are never plotted as street-level."}


@router.get("/cases/{case_id}/geo/layers")
async def geo_layers(request: Request, case_id: str):
    with S(request).sm() as db:
        case_for(db, request, case_id)
        return {"items": [{"id": g.id, "evidence_id": g.file_evidence_id, "crs": g.coordinate_system, "bounds": g.bounds_json,
                           "precision_class": g.precision_class, "pixel_size_m": g.pixel_size, "width": g.width,
                           "height": g.height, "licence": g.imagery_licence, "acquisition_time": g.acquisition_time}
                          for g in db.scalars(select(GeospatialLayer).where(GeospatialLayer.case_id == case_id))]}


# ---------------------------------------------------------------- signal / sensor re-analysis -----------------------------
class SpecIn(BaseModel):
    evidence_id: str
    nfft: int = Field(default=4096, ge=64, le=65536)
    max_peaks: int = Field(default=5, ge=1, le=20)


@router.post("/cases/{case_id}/signal/spectrogram")
async def spectrogram(request: Request, case_id: str, body: SpecIn):
    """Offline: recompute the spectrum of a stored SigMF archive with bounded FFT parameters. Stores nothing."""
    st = S(request)
    with st.sm() as db:
        case_for(db, request, case_id)
        ev, raw = _read_evidence(st, db, case_id, body.evidence_id)
    if ev.kind != "import.sigmf":
        raise ApiError(422, "wrong_kind", "evidence is not an imported SigMF archive")
    try:
        meta, data = parsers._read_sigmf_archive(raw)
        g = parsers.validate_sigmf_meta(meta)
        iq = parsers.decode_iq(data, g["core:datatype"])
        spec = await asyncio.to_thread(parsers.spectral_peaks, iq, float(g["core:sample_rate"]), body.nfft, body.max_peaks)
    except parsers.IngestError as exc:
        raise ApiError(422, "malformed_input", str(exc)) from exc
    return {"evidence_id": ev.id, "sample_rate_hz": g["core:sample_rate"], "spectrum": spec}


class SeriesIn(BaseModel):
    evidence_id: str
    z_threshold: float = Field(default=6.0, ge=2.0, le=50.0)


@router.post("/cases/{case_id}/sensor/series/analyze")
async def sensor_series(request: Request, case_id: str, body: SeriesIn):
    st = S(request)
    with st.sm() as db:
        case_for(db, request, case_id)
        ev, raw = _read_evidence(st, db, case_id, body.evidence_id)
    if ev.kind != "import.sensor_csv":
        raise ApiError(422, "wrong_kind", "evidence is not an imported sensor CSV")
    try:
        p = await asyncio.to_thread(parsers.parse_sensor_csv, raw, body.z_threshold)
    except parsers.IngestError as exc:
        raise ApiError(422, "malformed_input", str(exc)) from exc
    return {"evidence_id": ev.id, "result": p.observations[0].data}


# ---------------------------------------------------------------- STIX export ---------------------------------------------
@router.get("/cases/{case_id}/export/stix")
async def export_stix(request: Request, case_id: str):
    st = S(request)
    with st.sm() as db:
        case_for(db, request, case_id)
        ents = [{"id": e.id, "type": e.type, "key": e.canonical_key} for e in db.scalars(
            select(Entity).where(Entity.case_id == case_id, Entity.sensitivity != "RESTRICTED"))]
        rels = []
        for r in db.scalars(select(Relationship).where(Relationship.case_id == case_id, Relationship.status != "rejected")):
            rels.append({"from": r.from_entity_id, "to": r.to_entity_id, "type": r.relation_type, "status": r.status,
                         "confidence": r.confidence,
                         "evidence_ids": [x.evidence_id for x in db.scalars(select(RelationshipEvidence).where(
                             RelationshipEvidence.relationship_id == r.id))]})
        audit.record(db, "export.stix", actor=actor(request), case_id=case_id)
        db.commit()
    created = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    return net.export_stix(ents, rels, created)


# ---------------------------------------------------------------- sanctions screening --------------------------------------
class ScreenIn(BaseModel):
    entity_types: list[str] = Field(default_factory=lambda: ["company", "person", "organization"], max_length=10)


@router.post("/cases/{case_id}/sanctions/screen")
async def sanctions_screen(request: Request, case_id: str, body: ScreenIn):
    """Name-similarity SUGGESTIONS only: each hit becomes a pending graph proposal for the analyst. Nothing is merged
    and no entity is labelled sanctioned."""
    with S(request).sm() as db:
        case_for(db, request, case_id, "editor")
        entries: dict[str, list[dict[str, Any]]] = {}
        for o in db.scalars(select(Observation).where(Observation.case_id == case_id, Observation.kind == "fin.sanctions_entry")):
            d = o.data_json
            for nm in [d["name"], *d.get("aliases", [])]:
                entries.setdefault(fin.normalise_name(nm), []).append(d)
        if not entries:
            raise ApiError(409, "no_list", "no sanctions list has been imported into this case")
        created = 0
        items = []
        existing = {(p.subject_id, p.candidate_id) for p in db.scalars(select(GraphProposal).where(GraphProposal.case_id == case_id))}
        for e in db.scalars(select(Entity).where(Entity.case_id == case_id, Entity.type.in_(body.entity_types))):
            norm = fin.normalise_name(e.display_name.split(" (cik:")[0])
            for d in entries.get(norm, []):
                cand = db.scalars(select(Entity).where(Entity.case_id == case_id, Entity.type == "sanctions_entry",
                                                       Entity.display_name == d["name"])).first()
                if not cand:
                    continue
                items.append({"entity": e.display_name, "list_entry": d["name"], "list": d["list"], "id": d["id"]})
                if (e.id, cand.id) not in existing:
                    db.add(GraphProposal(case_id=case_id, proposal_type="sanctions_possible_match", subject_id=e.id,
                                         candidate_id=cand.id, reason="normalised-name similarity ONLY; verify identifiers "
                                                                      "(registry ID, address, DOB) before concluding anything"))
                    existing.add((e.id, cand.id))
                    created += 1
        audit.record(db, "sanctions.screen", actor=actor(request), case_id=case_id, metadata={"proposals": created})
        db.commit()
        return {"proposals_created": created, "possible_matches": items,
                "note": "These are leads for human review, not findings of sanctions status."}


_ = (Query, Any, hashlib)
