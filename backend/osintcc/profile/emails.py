"""Associated email addresses: evidence-linked candidates, explainable classification, analyst decisions, and the bridge to the shared graph.

Rules enforced here, not left to a screen:
  * an address becomes a candidate only when a stored source SHOWS it (a finding from a permitted adapter, an imported record, or a person's cited entry); the code never
    guesses and never tries a pattern. Pattern suggestions are returned separately, labelled speculative, are never stored by themselves and never drive follow-up work;
  * `classification` (confirmed / likely / possible / rejected) is derived from the sources, with the reasons stored beside it;
  * "likely" needs two INDEPENDENT sources that explicitly tie the address to the subject; one source, a bare co-occurrence or a conflicting owner stays "possible";
  * confirming needs the owner's attestation or independent corroboration, and records which; rejecting is sticky - new evidence is kept but nothing re-opens it;
  * a candidate is not an input: only a CONFIRMED address can be added to the subject's inputs (and then only inside what the authorization covers).
"""
from __future__ import annotations

import hashlib
import re
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db.models import (
    AssociatedEmail,
    Entity,
    Evidence,
    Finding,
    ProfileCandidateLink,
    ProfileReviewEvent,
    Relationship,
    RelationshipEvidence,
    ResearchTask,
    Subject,
    SubjectIdentifier,
)
from ..jobs.runner import upsert_entity
from ..telemetry import audit
from .normalize import mask_value
from .providers import BUILTIN as BUILTIN_SHARED
from .service import ProfileError, add_identifier, evidence_refs

ADDRESS = re.compile(r"^[a-z0-9._%+-]{1,64}@[a-z0-9-]{1,63}(?:\.[a-z0-9-]{1,63}){1,5}$")
STATES = ("candidate", "confirmed", "rejected")
CLASSES = ("confirmed", "likely", "possible", "rejected")
OBSERVED_PREDICATES = ("email.observed", "theharvester.email")
STRONG_KINDS = {"profile_field", "subject_page", "owner_provided", "analyst_evidence"}
GMAIL = {"gmail.com", "googlemail.com"}
FREEMAIL = frozenset(BUILTIN_SHARED)
REL_STATUS = {"confirmed": "manual", "rejected": "rejected", "candidate": "unverified"}
LABEL = {"confirmed": "Confirmed", "likely": "Likely", "possible": "Possible", "rejected": "Rejected"}


def _now() -> datetime:
    return datetime.now(UTC)


def normalize_address(addr: str) -> str | None:
    a = (addr or "").strip().strip("<>").lower()
    return a if ADDRESS.match(a) and len(a) <= 254 else None


def dedupe_key(addr: str) -> str:
    """Same mailbox, different spelling: case, Gmail dots and +tags. Other providers keep dots (they matter) but drop nothing else."""
    local, _, domain = addr.partition("@")
    if domain in GMAIL:
        local = local.split("+", 1)[0].replace(".", "")
        domain = "gmail.com"
    return f"{local}@{domain}"


def _sid(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]


# ---- subject context ------------------------------------------------------------------------------------------------------------------------
def _names(db: Session, subject: Subject) -> list[str]:
    out = {subject.display_name.strip().casefold()}
    for i in db.scalars(select(SubjectIdentifier).where(SubjectIdentifier.subject_id == subject.id, SubjectIdentifier.status == "active")):
        if i.kind in ("name", "alias", "username"):
            out.add(i.value.strip().casefold())
    out.discard("")
    return sorted(out)


def _inputs(db: Session, subject: Subject) -> dict[str, set[str]]:
    d: dict[str, set[str]] = {}
    for i in db.scalars(select(SubjectIdentifier).where(SubjectIdentifier.subject_id == subject.id, SubjectIdentifier.status == "active")):
        d.setdefault(i.kind, set()).add(i.value.casefold())
    return d


def identifier_depth(db: Session, ident: SubjectIdentifier) -> tuple[int, list[str]]:
    """How many hops from the subject's own inputs this identifier is, and the chain that led to it (an input is depth 0)."""
    row = db.scalars(select(AssociatedEmail).where(AssociatedEmail.identifier_id == ident.id)).first()
    return (row.depth, list(row.origin_path)) if row else (0, [])


def _mentions_subject(text: str, names: list[str]) -> bool:
    t = text.casefold()
    return any(len(n) >= 3 and n in t for n in names)


def _name_matches(hint: str, names: list[str]) -> bool:
    h = hint.casefold().strip()
    if not h:
        return True                                           # no owner hint: nothing to contradict
    toks = {t for t in re.split(r"[^a-z0-9]+", h) if len(t) >= 3}
    for n in names:
        nt = {t for t in re.split(r"[^a-z0-9]+", n) if len(t) >= 3}
        if h == n or (toks & nt) and (len(nt) == 1 or len(toks & nt) >= 2 or n in h or h in n):
            return True
    return False


# ---- classification -------------------------------------------------------------------------------------------------------------------------
def classify(row: AssociatedEmail) -> tuple[str, list[str]]:
    why: list[str] = []
    if row.state == "rejected":
        return "rejected", [f"Rejected by {row.reviewed_by or 'an analyst'}: {row.review_basis}"[:240]]
    if row.state == "confirmed":
        kind = {"analyst_attested": "attested by the owner or analyst", "independently_corroborated": "corroborated by independent sources"}.get(row.confirmation_kind or "", "decided by an analyst")
        return "confirmed", [f"Confirmed by {row.reviewed_by or 'an analyst'}: {kind}."]
    explicit = [s for s in row.sources if s.get("explicit")]
    groups = {s.get("group") for s in explicit}
    if row.origin == "speculative" and not row.sources:
        return "possible", ["A pattern guess, not an observed address. Nothing was found that shows it exists or belongs to the subject."]
    if row.conflicts:
        why += [f"Conflict: {c['detail']}." for c in row.conflicts]
        why.append("An address with conflicting ownership evidence stays Possible until a person resolves it.")
        return "possible", why
    if len(groups) >= 2:
        why.append(f"{len(groups)} independent sources explicitly tie this address to the subject ({', '.join(sorted(str(g) for g in groups))}).")
        return "likely", why
    if len(groups) == 1:
        why.append(f"One source ties it to the subject explicitly ({next(iter(groups))}); a second independent source or the owner's confirmation is needed for Likely.")
    elif row.sources:
        why.append("Seen in the evidence, but no source says it belongs to the subject (it appears near, or alongside, other content).")
    return "possible", why


def _recompute(row: AssociatedEmail) -> None:
    row.classification, row.explanation = classify(row)


# ---- sources --------------------------------------------------------------------------------------------------------------------------------
def make_source(kind: str, group: str, *, explicit: bool, evidence_id: str | None = None, finding_id: str | None = None, url: str = "", context: str = "", owner_hint: str = "",
                adapter: str = "", observed_at: datetime | None = None, basis: str = "", via: str = "") -> dict[str, Any]:
    from ..darkint.sanitize import sanitize_text
    context = sanitize_text(context, 200)[0]                  # a passage around an address can hold anything: secrets and other people's addresses are redacted before it is stored
    return {"id": _sid(kind, group, evidence_id or "", url, context[:60]), "kind": kind, "group": group, "explicit": bool(explicit), "evidence_id": evidence_id, "finding_id": finding_id,
            "url": url[:300], "via": via[:120], "context": context, "owner_hint": owner_hint[:120], "adapter": adapter, "basis": basis[:200],
            "observed_at": (observed_at or _now()).isoformat()}


def _conflicts(db: Session, subject: Subject, row: AssociatedEmail, names: list[str]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for s in row.sources:
        hint = s.get("owner_hint") or ""
        if hint and not _name_matches(hint, names):
            out.append({"kind": "different_name", "detail": f"a source attributes the address to '{hint}', which does not match the subject's known names", "source": s["id"]})
    mine = row.dedupe_key
    for i in db.scalars(select(SubjectIdentifier).where(SubjectIdentifier.case_id == subject.case_id, SubjectIdentifier.subject_id != subject.id, SubjectIdentifier.kind == "email",
                                                       SubjectIdentifier.status == "active")):
        if dedupe_key(i.value) == mine:
            out.append({"kind": "other_subject_input", "detail": "another subject in this case lists this address as its own input"})
            break
    for o in db.scalars(select(AssociatedEmail).where(AssociatedEmail.case_id == subject.case_id, AssociatedEmail.subject_id != subject.id, AssociatedEmail.dedupe_key == mine,
                                                     AssociatedEmail.state == "confirmed")):
        out.append({"kind": "other_subject_confirmed", "detail": "this address is confirmed as belonging to another subject in this case"})
        break
    return out


def add_source(db: Session, subject: Subject, address: str, source: dict[str, Any], *, origin: str = "observed", depth: int = 0, origin_path: list[str] | None = None,
               actor: str = "system") -> tuple[AssociatedEmail | None, bool]:
    a = normalize_address(address)
    if a is None:
        return None, False
    key = dedupe_key(a)
    inputs = _inputs(db, subject)
    if key in {dedupe_key(v) for v in inputs.get("email", set())}:
        return None, False                                    # the subject's own input is not an "associated" address
    row = db.scalars(select(AssociatedEmail).where(AssociatedEmail.subject_id == subject.id, AssociatedEmail.dedupe_key == key)).first()
    created = row is None
    names = _names(db, subject)
    if created:
        row = AssociatedEmail(subject_id=subject.id, case_id=subject.case_id, address=a, dedupe_key=key, origin=origin, sources=[], associations={}, aliases=[], depth=depth,
                              origin_path=origin_path or [], discovered_at=_now())
        db.add(row)
        db.flush()
    assert row is not None
    if a != row.address and a not in row.aliases:
        row.aliases = [*row.aliases, a]                      # a different spelling of the same mailbox keeps its own provenance below
    if source["id"] not in {s["id"] for s in row.sources}:
        row.sources = [*row.sources, source]
        if row.origin == "speculative" and source.get("kind") != "pattern_guess":
            row.origin = "observed"
    if row.depth > depth:
        row.depth, row.origin_path = depth, origin_path or row.origin_path
    row.associations = _associations(db, subject, row)
    row.conflicts = _conflicts(db, subject, row, names)
    _recompute(row)
    if created:
        audit.record(db, "profile.email_discovered", actor=actor, case_id=subject.case_id, resource_type="associated_email", resource_id=row.id,
                     metadata={"origin": origin, "kind": source.get("kind"), "classification": row.classification})
    db.flush()
    return row, created


def _associations(db: Session, subject: Subject, row: AssociatedEmail) -> dict[str, Any]:
    users, domains, docs, accts = set(), set(), set(), set()
    for s in row.sources:
        if s.get("kind") in ("profile_field", "commit_author") and s.get("group") == "github":
            users.add(str(s.get("via") or ""))
        if s.get("evidence_id"):
            docs.add(s["evidence_id"])
        host = re.sub(r"^https?://", "", s.get("url", "")).split("/")[0]
        if host:
            domains.add(host.lower())
    domains.add(row.address.split("@")[1])
    for c in db.scalars(select(ProfileCandidateLink).where(ProfileCandidateLink.subject_id == subject.id)):
        if any(c.canonical_url and s.get("url") and c.canonical_url.rstrip("/") in s["url"] for s in row.sources):
            accts.add(c.id)
    users.discard("")
    return {"usernames": sorted(users), "domains": sorted(domains), "documents": sorted(docs), "accounts": sorted(accts)}


# ---- sweep: existing evidence, no network ---------------------------------------------------------------------------------------------------
def sweep(db: Session, subject: Subject, actor: str = "system") -> dict[str, int]:
    """Fold addresses that stored evidence already shows into candidates. Reads only the case's own records; contacts nothing."""
    names = _names(db, subject)
    inputs = _inputs(db, subject)
    tasks = {(t.run_id, t.source_id): t for t in db.scalars(select(ResearchTask).where(ResearchTask.subject_id == subject.id)) if t.run_id}
    run_ids = {k[0] for k in tasks}
    created = updated = 0
    for f in db.scalars(select(Finding).where(Finding.case_id == subject.case_id, Finding.predicate.in_(OBSERVED_PREDICATES))):
        if f.run_id not in run_ids:
            continue                                         # findings from searches nobody attached to this subject are not its evidence
        v = f.value_json if isinstance(f.value_json, dict) else {"address": str(f.value_json)}
        addr = v.get("address") or (f.value_json if isinstance(f.value_json, str) else "")
        ctx = str(v.get("context") or "")
        kind = str(v.get("via_kind") or ("harvester_result" if f.predicate == "theharvester.email" else "case_finding"))
        explicit = bool(v.get("explicit"))
        basis = ""
        via = str(v.get("via") or "")
        if kind == "profile_field":
            basis = f"listed on the public profile of handle {via}"
        elif kind == "commit_author":
            basis = f"author address on commits pushed by handle {via}"
        elif ctx and _mentions_subject(ctx, names):
            explicit, basis = True, "the subject's name or handle appears in the same passage"
        elif kind == "harvester_result":
            d = str(addr).partition("@")[2].lower()
            basis = "found on a domain the subject lists" if d in inputs.get("domain", set()) else "found by a passive domain search"
        src = make_source(kind if kind in ("profile_field", "commit_author") else "page_mention" if kind in ("mailto_link", "page_text", "obfuscated_text") else kind,
                          str(v.get("group") or f"adapter:{f.adapter_id}"), explicit=explicit, evidence_id=f.evidence_id, finding_id=f.id, url=str(v.get("url") or ""), context=ctx,
                          owner_hint=str(v.get("owner_hint") or ""), adapter=f.adapter_id, observed_at=f.observed_at, basis=basis, via=via)
        depth, path = 1, []
        task = tasks.get((f.run_id, f.adapter_id))
        parent = db.get(SubjectIdentifier, task.identifier_id) if task and task.identifier_id else None
        if parent is not None:
            pd, pp = identifier_depth(db, parent)
            depth = pd + 1
            path = [*(pp or ["subject input"]), f"{f.adapter_id} on {mask_value(parent.kind, parent.value) if parent.kind in ('email', 'name', 'alias') else parent.value} shows {mask_value('email', str(addr))}"]
        row, new = add_source(db, subject, str(addr), src, depth=depth, origin_path=path, actor=actor)
        if row is not None:
            created += int(new)
            updated += int(not new)
    created += _sweep_observations(db, subject, names, actor)
    db.flush()
    for r in db.scalars(select(AssociatedEmail).where(AssociatedEmail.subject_id == subject.id)):
        sync_graph(db, subject, r)
    return {"created": created, "updated": updated}


def _sweep_observations(db: Session, subject: Subject, names: list[str], actor: str) -> int:
    """Imported records from other disciplines (messages, documents): an address counts only if the same record also names the subject."""
    from ..db.models import Observation
    n = 0
    email_re = re.compile(r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){1,5}")
    for o in db.scalars(select(Observation).where(Observation.case_id == subject.case_id).limit(2000)):
        if o.sensitivity in ("RESTRICTED", "SECRET"):
            continue
        blob = " ".join(str(v) for v in (o.data_json or {}).values() if isinstance(v, str | list))[:4000]
        found = {m.lower() for m in email_re.findall(blob)}
        if not found or not _mentions_subject(blob, names):
            continue
        for addr in sorted(found)[:20]:
            src = make_source("case_observation", f"discipline:{o.discipline_id}", explicit=False, evidence_id=o.raw_evidence_id, context=f"{o.kind} record from the {o.discipline_id} module",
                              adapter=o.discipline_id, observed_at=o.observed_at or o.ingested_at, basis="appears in an imported record that also names the subject")
            row, new = add_source(db, subject, addr, src, actor=actor)
            n += int(row is not None and new)
    return n


# ---- speculative suggestions (never stored on their own) ---------------------------------------------------------------------------------
def speculate(db: Session, subject: Subject) -> list[dict[str, Any]]:
    """Pattern guesses from a known name and a domain the subject owns. Labelled speculative; they do not exist as candidates until a person accepts one."""
    inputs = _inputs(db, subject)
    domains = sorted(inputs.get("domain", set()))
    parts = [p for p in re.split(r"[^a-z]+", subject.display_name.casefold()) if len(p) >= 2]
    if not domains or len(parts) < 2:
        return []
    first, last = parts[0], parts[-1]
    pats = [f"{first}.{last}", f"{first[0]}{last}", f"{first}", f"{first}{last[0]}", f"{last}"]
    have = {r.dedupe_key for r in db.scalars(select(AssociatedEmail).where(AssociatedEmail.subject_id == subject.id))}
    out = []
    for d in domains[:3]:
        for p in pats:
            a = f"{p}@{d}"
            if dedupe_key(a) not in have:
                out.append({"address": a, "origin": "speculative", "label": "Speculative pattern guess - not observed anywhere",
                            "note": "Shown so you can decide whether to look for evidence. It is not stored, searched or checked until you accept it, and it can never be confirmed without evidence."})
    return out[:15]


def accept_speculative(db: Session, subject: Subject, address: str, actor: str) -> AssociatedEmail:
    a = normalize_address(address)
    if a is None:
        raise ProfileError("invalid_address", "that is not a valid email address")
    if a not in {s["address"] for s in speculate(db, subject)}:
        raise ProfileError("not_suggested", "only a pattern suggested for this subject can be accepted as a speculative candidate")
    row = AssociatedEmail(subject_id=subject.id, case_id=subject.case_id, address=a, dedupe_key=dedupe_key(a), origin="speculative", sources=[], associations={}, aliases=[], discovered_at=_now())
    db.add(row)
    db.flush()
    _recompute(row)
    audit.record(db, "profile.email_speculative", actor=actor, case_id=subject.case_id, resource_type="associated_email", resource_id=row.id)
    return row


def add_manual(db: Session, subject: Subject, address: str, *, evidence_id: str | None, url: str, note: str, actor: str) -> AssociatedEmail:
    """A person records an address with the evidence that shows it. Without evidence it is a lead the person typed, and says so."""
    a = normalize_address(address)
    if a is None:
        raise ProfileError("invalid_address", "that is not a valid email address")
    if evidence_id:
        ev = db.get(Evidence, evidence_id)
        if not ev or ev.case_id != subject.case_id:
            raise ProfileError("evidence_not_in_case", "evidence is not in this case")
    src = make_source("analyst_evidence" if evidence_id else "analyst_note", f"analyst:{actor}", explicit=bool(evidence_id), evidence_id=evidence_id, url=url, context=note,
                      basis="entered by an analyst" + (" with cited evidence" if evidence_id else " without evidence"))
    row, _ = add_source(db, subject, a, src, origin="analyst_entered", actor=actor)
    if row is None:
        raise ProfileError("already_an_input", "that address is already one of this subject's own inputs")
    sync_graph(db, subject, row)
    return row


# ---- decisions ------------------------------------------------------------------------------------------------------------------------------
def review(db: Session, subject: Subject, ids: list[str], *, to_state: str, reviewer: str, basis: str, attestation: str = "none", evidence_ids: list[str] | None = None) -> dict[str, Any]:
    if to_state not in STATES:
        raise ProfileError("invalid_state", "state must be confirmed, rejected or candidate")
    if not ids:
        raise ProfileError("nothing_selected", "select at least one address")
    if len(ids) > 200:
        raise ProfileError("too_many", "review at most 200 addresses at a time")
    if not basis.strip():
        raise ProfileError("basis_required", "record the reason or method for this decision")
    if attestation not in ("none", "subject"):
        raise ProfileError("invalid_attestation", "attestation must be 'subject' (the owner attests) or 'none'")
    extra = list(dict.fromkeys(evidence_ids or []))
    for eid in extra:
        ev = db.get(Evidence, eid)
        if not ev or ev.case_id != subject.case_id:
            raise ProfileError("evidence_not_in_case", f"evidence {eid} is not in this case")
    rows = []
    for i in ids:
        r = db.get(AssociatedEmail, i)
        if not r or r.subject_id != subject.id:
            raise ProfileError("not_found", f"address {i} not found")
        rows.append(r)
    plan: dict[str, str] = {}
    if to_state == "confirmed":
        for r in rows:
            kind = _confirmation_kind(r, attestation, extra)
            if kind is None:
                raise ProfileError("corroboration_required", f"{mask_value('email', r.address)}: confirming needs the owner's attestation, or independent evidence that explicitly ties the address "
                                   "to the subject from a second source; the address appearing in the evidence is not enough")
            plan[r.id] = kind
    bulk = str(uuid.uuid4()) if len(rows) > 1 else None
    for r in rows:
        prev = r.state
        r.state, r.reviewed_by, r.reviewed_at, r.review_basis = to_state, reviewer, _now(), basis.strip()
        if to_state == "confirmed":
            r.confirmation_kind = plan[r.id]
            for eid in extra:
                r.sources = [*r.sources, make_source("analyst_evidence", f"analyst:{reviewer}", explicit=True, evidence_id=eid, basis="cited by the reviewer when confirming")]
        else:
            r.confirmation_kind = None
        r.last_verified_at = _now()
        _recompute(r)
        db.add(ProfileReviewEvent(subject_id=subject.id, case_id=subject.case_id, target_type="email", target_id=r.id, from_state=prev, to_state=to_state, reviewer=reviewer,
                                  basis=basis.strip(), attestation=("subject" if attestation == "subject" else "corroborated" if plan.get(r.id) == "independently_corroborated" else "none"),
                                  evidence_ids=extra, bulk_id=bulk))
        sync_graph(db, subject, r)
    audit.record(db, "profile.email_review", actor=reviewer, case_id=subject.case_id, resource_type="subject", resource_id=subject.id, metadata={"count": len(rows), "to": to_state, "bulk_id": bulk or ""})
    db.flush()
    return {"updated": len(rows), "bulk_id": bulk, "state": to_state}


def _confirmation_kind(r: AssociatedEmail, attestation: str, extra: list[str]) -> str | None:
    if attestation == "subject":
        return "analyst_attested"
    if r.conflicts:
        return None                                           # a conflict has to be resolved by the owner's own word, not by more sightings
    have = {s.get("evidence_id") for s in r.sources}
    groups = {s.get("group") for s in r.sources if s.get("explicit")}
    new = [e for e in extra if e not in have]
    if len(groups) >= 2 or (groups and new):
        return "independently_corroborated"
    return None


def annotate(db: Session, subject: Subject, email_id: str, note: str, actor: str) -> AssociatedEmail:
    r = db.get(AssociatedEmail, email_id)
    if not r or r.subject_id != subject.id:
        raise ProfileError("not_found", "address not found")
    r.note = " ".join(note.split())[:1000]
    audit.record(db, "profile.email_note", actor=actor, case_id=subject.case_id, resource_type="associated_email", resource_id=r.id)
    return r


# ---- duplicates -----------------------------------------------------------------------------------------------------------------------------
def duplicate_groups(db: Session, subject: Subject) -> list[dict[str, Any]]:
    """Addresses that probably name the same mailbox: same local part ignoring a +tag, or the same Gmail mailbox. Suggestions only."""
    rows = list(db.scalars(select(AssociatedEmail).where(AssociatedEmail.subject_id == subject.id)))
    by: dict[str, list[AssociatedEmail]] = {}
    for r in rows:
        local, _, dom = r.dedupe_key.partition("@")
        by.setdefault(f"{local.split('+', 1)[0]}@{dom}", []).append(r)
    return [{"key": k, "ids": [r.id for r in v], "addresses": [mask_value("email", r.address) for r in v]} for k, v in by.items() if len(v) > 1]


def merge(db: Session, subject: Subject, keep_id: str, merge_ids: list[str], actor: str) -> AssociatedEmail:
    keep = db.get(AssociatedEmail, keep_id)
    if not keep or keep.subject_id != subject.id:
        raise ProfileError("not_found", "address not found")
    for mid in merge_ids:
        m = db.get(AssociatedEmail, mid)
        if not m or m.subject_id != subject.id or m.id == keep.id:
            raise ProfileError("not_found", f"address {mid} not found")
        if m.state == "confirmed" and keep.state != "confirmed" or m.state != keep.state and "rejected" in (m.state, keep.state):
            raise ProfileError("merge_conflict", "addresses with different decisions cannot be merged; resolve the decisions first")
        known = {s["id"] for s in keep.sources}
        keep.sources = [*keep.sources, *[s for s in m.sources if s["id"] not in known]]       # every original source and its provenance survives the merge
        keep.aliases = sorted({*keep.aliases, m.address, *m.aliases} - {keep.address})
        keep.depth = min(keep.depth, m.depth)
        db.delete(m)
    keep.associations = _associations(db, subject, keep)
    keep.conflicts = _conflicts(db, subject, keep, _names(db, subject))
    _recompute(keep)
    audit.record(db, "profile.email_merge", actor=actor, case_id=subject.case_id, resource_type="associated_email", resource_id=keep.id, metadata={"merged": len(merge_ids)})
    db.flush()
    sync_graph(db, subject, keep)
    return keep


# ---- inputs and the graph --------------------------------------------------------------------------------------------------------------------
def promote(db: Session, subject: Subject, email_id: str, actor: str) -> SubjectIdentifier:
    r = db.get(AssociatedEmail, email_id)
    if not r or r.subject_id != subject.id:
        raise ProfileError("not_found", "address not found")
    if r.state != "confirmed":
        raise ProfileError("not_confirmed", "only a confirmed address can be added as an input; a candidate cannot authorize research or exposure checks")
    ev = next((s["evidence_id"] for s in r.sources if s.get("evidence_id")), None)
    ident = add_identifier(db, subject, "email", r.address, actor=actor, source_evidence_id=ev)
    r.identifier_id = ident.id
    audit.record(db, "profile.email_promote", actor=actor, case_id=subject.case_id, resource_type="associated_email", resource_id=r.id)
    return ident


def sync_graph(db: Session, subject: Subject, r: AssociatedEmail) -> None:
    """The address becomes an entity in the case graph, linked to what showed it, with the decision as the relationship status. Idempotent."""
    from ..adapters.base import EntityRef
    ent = upsert_entity(db, subject.case_id, EntityRef(type="email", key=r.address, display=r.address))
    r.entity_id = ent.id
    anchors: list[Entity] = []
    for s in r.sources:
        for etype, key in (("username", s.get("via", "") if s.get("group") == "github" else ""), ("url", s.get("url", ""))):
            if key:
                e = db.scalars(select(Entity).where(Entity.case_id == subject.case_id, Entity.type == etype, Entity.canonical_key == key)).first()
                if e and e not in anchors:
                    anchors.append(e)
    for a in anchors[:5]:
        rel = db.scalars(select(Relationship).where(Relationship.case_id == subject.case_id, Relationship.from_entity_id == a.id, Relationship.to_entity_id == ent.id,
                                                    Relationship.relation_type == "associated_email")).first()
        status = REL_STATUS[r.state]
        if rel is None:
            rel = Relationship(case_id=subject.case_id, from_entity_id=a.id, to_entity_id=ent.id, relation_type="associated_email", status=status,
                               confidence={"confirmed": "high", "likely": "medium"}.get(r.classification, "low"), confidence_reason="; ".join(r.explanation)[:480],
                               asserted_by=r.reviewed_by if r.state != "candidate" and r.reviewed_by else "profile.emails")
            db.add(rel)
            db.flush()
        else:
            rel.status, rel.confidence_reason = status, "; ".join(r.explanation)[:480]
            rel.confidence = {"confirmed": "high", "likely": "medium"}.get(r.classification, "low")
            if r.state != "candidate" and r.reviewed_by:
                rel.asserted_by = r.reviewed_by
        have = {x.evidence_id for x in db.scalars(select(RelationshipEvidence).where(RelationshipEvidence.relationship_id == rel.id))}
        for s in r.sources:
            if s.get("evidence_id") and s["evidence_id"] not in have and db.get(Evidence, s["evidence_id"]):
                db.add(RelationshipEvidence(relationship_id=rel.id, evidence_id=s["evidence_id"]))
                have.add(s["evidence_id"])


# ---- presentation ---------------------------------------------------------------------------------------------------------------------------
def email_dict(db: Session, st: Any, subject: Subject, r: AssociatedEmail, *, redact: bool) -> dict[str, Any]:
    exposure: dict[str, Any] = {"state": "not_an_input", "label": "Not checked", "note": "A candidate is not an authorized input, so no exposure provider is asked about it. Confirm it and add it as an input first."}
    if r.identifier_id:
        try:
            from ..darkint import service as dsvc
            cov = next((c for c in dsvc.coverage(db, st, subject)["items"] if c["identifier_id"] == r.identifier_id), None)
            if cov:
                evs = [e for e in dsvc.grouped_events(db, subject, redact=True) if any(x["identifier_id"] == r.identifier_id for x in e["events"])]
                cats = sorted({c for g in evs for c in g["categories"]})
                exposure = {"state": cov["state"], "label": cov["label"], "note": cov["meaning"], "categories": cats, "credential_indicator": "credential indicator" in cats,
                            "reports": len(evs), "recommend": ["Change the password and turn on multi-factor authentication for accounts using this address."] if "credential indicator" in cats else []}
        except Exception as exc:                             # exposure data is optional on this screen
            exposure["note"] = f"exposure data unavailable ({type(exc).__name__})"
    out: dict[str, Any] = {"id": r.id, "address": mask_value("email", r.address) if redact else r.address, "masked": redact, "classification": r.classification, "label": LABEL[r.classification],
           "state": r.state, "origin": r.origin, "origin_label": {"observed": "Observed in a source", "analyst_entered": "Entered by an analyst", "speculative": "Speculative pattern guess"}[r.origin],
           "explanation": r.explanation, "confirmation_kind": r.confirmation_kind, "conflicts": r.conflicts, "associations": r.associations, "aliases": [] if redact else r.aliases,
           "depth": r.depth, "origin_path": r.origin_path, "discovered_at": r.discovered_at, "last_verified_at": r.last_verified_at, "reviewed_by": r.reviewed_by, "reviewed_at": r.reviewed_at,
           "review_basis": r.review_basis, "note": r.note, "is_input": bool(r.identifier_id), "exposure": exposure,
           "sources": [{k: s.get(k) for k in ("id", "kind", "group", "explicit", "evidence_id", "url", "context", "adapter", "basis", "observed_at", "via")} for s in r.sources],
           "evidence": evidence_refs(db, sorted({s["evidence_id"] for s in r.sources if s.get("evidence_id")}))}
    if redact:
        for s in out["sources"]:
            s["context"] = ""
    return out


def list_for(db: Session, st: Any, subject: Subject, *, role: str) -> dict[str, Any]:
    redact = role not in ("owner", "editor")
    rows = list(db.scalars(select(AssociatedEmail).where(AssociatedEmail.subject_id == subject.id).order_by(AssociatedEmail.discovered_at)))
    order = {c: i for i, c in enumerate(CLASSES)}
    rows.sort(key=lambda r: (order[r.classification], r.discovered_at))
    counts = {c: sum(1 for r in rows if r.classification == c) for c in CLASSES}
    inputs = [{"id": f"input:{i.id}", "address": mask_value("email", i.value) if redact else i.value, "masked": redact, "label": "Your input", "origin": "input", "identifier_id": i.id,
               "note": "An address you provided. It is researched as an input where the authorization allows; it is not an associated address and not a verified claim.",
               "domain_research": "none: a mailbox provider's or a custom domain's records are not researched from an email address alone"}
              for i in db.scalars(select(SubjectIdentifier).where(SubjectIdentifier.subject_id == subject.id, SubjectIdentifier.kind == "email", SubjectIdentifier.status == "active"))]
    return {"inputs": inputs, "items": [email_dict(db, st, subject, r, redact=redact) for r in rows], "counts": counts, "duplicates": duplicate_groups(db, subject) if not redact else [],
            "legend": {"confirmed": "A person confirmed it with the owner's attestation or independent corroboration.", "likely": "Two independent sources explicitly tie it to the subject.",
                       "possible": "Seen in evidence, but not tied to the subject by enough independent sources, or the evidence conflicts.", "rejected": "A person decided it does not belong to the subject. Nothing is researched from it."},
            "notice": "An address found in a source is a candidate, never a fact. Guessed patterns are never presented as discoveries."}
