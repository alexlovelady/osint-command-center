"""Persists a ParsedIngest: inert evidence + canonical observations + (evidence-linked) entities/claims."""
from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db.models import (
    Entity,
    Evidence,
    Finding,
    GeospatialLayer,
    Observation,
    Relationship,
    RelationshipEvidence,
)
from ..evidence.vault import Vault
from ..telemetry import audit
from .parsers import PARSER_VERSION, ParsedIngest


def persist(db: Session, vault: Vault, case_id: str, parsed: ParsedIngest, raw: bytes, filename: str,
            actor: str, sensitivity: str | None = None) -> dict:
    sha256, sha512, rel, size = vault.store(raw)
    now = datetime.now(UTC)
    sens = sensitivity or parsed.sensitivity
    ev = db.scalars(select(Evidence).where(Evidence.case_id == case_id, Evidence.sha256 == sha256,
                                           Evidence.kind == f"import.{parsed.kind}")).first()
    created = ev is None
    if created:
        ev = Evidence(case_id=case_id, kind=f"import.{parsed.kind}", title=filename, sha256=sha256, sha512=sha512,
                      byte_size=size, mime_type=parsed.mime,
                      vault_relpath=rel, retrieved_at=now, observed_at=now, capture_method="manual_import",
                      sensitivity=sens, created_by=actor,
                      description=f"{parsed.discipline} import ({parsed.kind}); stored inert, parser {PARSER_VERSION}",
                      chain_of_custody_json=[{"event": "imported", "at": now.isoformat(), "by": actor,
                                              "sha256": sha256, "ownership_confirmed": True}])
        db.add(ev)
        db.flush()
    assert ev is not None
    n_obs = 0
    existing_keys = {hashlib.sha256(json.dumps([o.kind, o.data_json], sort_keys=True, default=str).encode()).hexdigest()
                     for o in db.scalars(select(Observation).where(Observation.raw_evidence_id == ev.id))}
    for o in parsed.observations:
        key = hashlib.sha256(json.dumps([o.kind, o.data], sort_keys=True, default=str).encode()).hexdigest()
        if key in existing_keys:
            continue  # re-importing the same file adds nothing
        db.add(Observation(case_id=case_id, discipline_id=o.discipline, kind=o.kind,
                           access_class=parsed.access_class, observed_at=o.observed_at, ingested_at=now,
                           data_json=o.data, raw_evidence_id=ev.id, sensitivity=o.sensitivity or sens,
                           confidence=o.confidence, parser_version=PARSER_VERSION))
        n_obs += 1
    ents: dict[tuple[str, str], Entity] = {}
    for e in parsed.entities:
        row = db.scalars(select(Entity).where(Entity.case_id == case_id, Entity.type == e.type,
                                              Entity.canonical_key == e.key)).first()
        if not row:
            row = Entity(case_id=case_id, type=e.type, canonical_key=e.key, display_name=e.display,
                         sensitivity=sens, first_seen_at=now, last_seen_at=now)
            db.add(row)
            db.flush()
        ents[(e.type, e.key)] = row
    n_rel = 0
    for r in parsed.relationships:
        a, b = ents[r.from_key], ents[r.to_key]
        rel_row = db.scalars(select(Relationship).where(
            Relationship.case_id == case_id, Relationship.from_entity_id == a.id, Relationship.to_entity_id == b.id,
            Relationship.relation_type == r.relation_type)).first()
        if not rel_row:
            rel_row = Relationship(case_id=case_id, from_entity_id=a.id, to_entity_id=b.id,
                                   relation_type=r.relation_type, confidence="unknown", confidence_reason=r.reason,
                                   status="unverified", asserted_by=f"import:{parsed.kind}")
            db.add(rel_row)
            db.flush()
            n_rel += 1
        if not db.get(RelationshipEvidence, (rel_row.id, ev.id)):
            db.add(RelationshipEvidence(relationship_id=rel_row.id, evidence_id=ev.id))
    for lay in parsed.layers:
        db.add(GeospatialLayer(case_id=case_id, file_evidence_id=ev.id, **lay))
    if parsed.kind == "eml" and parsed.observations:
        for who in parsed.entities[:1]:
            key = hashlib.sha256(f"{case_id}:{ev.id}:email.claimed_sender".encode()).hexdigest()
            if not db.scalars(select(Finding.id).where(Finding.case_id == case_id, Finding.dedup_key == key)).first():
                db.add(Finding(case_id=case_id, subject_entity_id=ents[(who.type, who.key)].id,
                               predicate="email.claimed_sender", value_type="str", value_json="message header claim",
                               confidence="unknown", confidence_reason="From header is a claim; not authenticated",
                               evidence_id=ev.id, adapter_id="import.eml", adapter_version=PARSER_VERSION,
                               observed_at=now, dedup_key=key))
    audit.record(db, "ingest.import", actor=actor, case_id=case_id, resource_type="evidence", resource_id=ev.id,
                 metadata={"kind": parsed.kind, "bytes": size, "observations": n_obs, "new_evidence": created})
    return {"evidence_id": ev.id, "sha256": sha256, "kind": parsed.kind, "discipline": parsed.discipline,
            "observations_added": n_obs, "relationships_added": n_rel, "summary": parsed.summary,
            "warnings": parsed.warnings, "duplicate_evidence": not created}
