"""The Master Profile Editor: one place to read and write everything known about a subject, backed by the records the rest of the application already uses.

  * Inputs (email, username, domain, URL, name, alias, organization) are written through `add_identifier`, so the research planner, Associated Emails and the expansion plan see them
    at once: there is no second entry.
  * Employment, education and publications are written as profile claims, so claim review and reports keep working.
  * Everything else (contact points, locations, devices, relationships, custom attributes) lives in `profile_items`.
  * Images, exposure records, discovered candidates and associated addresses are shown as read-only entries from their own stores: nothing is copied, nothing drifts.

An empty category means NOT RESEARCHED, never "nothing exists". Competing and contradictory items are kept. A discovered item is a candidate and never an owned or authorized
identifier. Self-attestation is recorded as self-attestation and can never become corroboration. Restricted values are filtered on the server: viewers do not receive them, editors
see them masked, only an owner can reveal one (with a reason, audited), and reference-only values (identity-document or SSN references) are stored as a keyed token and a masked form,
never as the number.
"""
from __future__ import annotations

import csv
import hashlib
import hmac
import io
import json
import re
import secrets
import uuid
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db.models import (
    Evidence,
    ExposureIndicator,
    Finding,
    ImageAsset,
    ProfileCandidateLink,
    ProfileClaim,
    ProfileItem,
    ProfileReviewEvent,
    ResearchTask,
    Setting,
    Subject,
    SubjectIdentifier,
)
from ..telemetry import audit
from . import candidates, consent, emails
from .normalize import IdentifierError, canonical_url, normalize_identifier
from .service import ProfileError, add_claim, add_identifier, evidence_refs, remove_identifier, review_claim

CATEGORIES = [("identity", "Identity"), ("contact", "Contact"), ("locations", "Locations"), ("education", "Education"), ("employment", "Employment"), ("online_footprint", "Online footprint"),
              ("business", "Business and organizations"), ("devices", "Devices and infrastructure"), ("images_documents", "Images and documents"), ("security_exposure", "Security exposure"),
              ("relationships", "Relationships"), ("timeline", "Timeline"), ("custom", "Custom attributes")]
STATES = ("unassessed", "candidate", "corroborated", "conflicting", "rejected", "not_available")
# Stored states are STATES. "self_attested" is a DISPLAY state: an owner's own confirmation, shown apart from independent corroboration.
DISPLAY_STATES = (*STATES, "self_attested")
STATE_LABEL = {"unassessed": "Unassessed", "candidate": "Candidate", "corroborated": "Independently corroborated", "conflicting": "Conflicting", "rejected": "Rejected", "not_available": "Not available",
               "self_attested": "Self-attested"}
ORIGINS = ("subject_provided", "analyst_supplied", "published_source", "verified_provider", "discovered")
METHODS = ("manual", "import")
RESTRICTED_NOTE = "Restricted: shown masked. An owner can reveal it with a reason; the reveal is audited. It is never exported, indexed or sent to a model."


def T(category: str, label: str, *, identifier: str | None = None, claim: str | None = None, restricted: bool = False, single: bool = False, reference: bool = False,
      sensitivity: str = "INTERNAL") -> dict[str, Any]:
    return {"category": category, "label": label, "identifier": identifier, "claim": claim, "restricted": restricted or reference, "single": single, "reference": reference,
            "sensitivity": "RESTRICTED" if restricted or reference else sensitivity}


TYPES: dict[str, dict[str, Any]] = {
    "full_name": T("identity", "Full name", identifier="name"), "alias": T("identity", "Alias or alternate name", identifier="alias"),
    "date_of_birth": T("identity", "Date of birth", restricted=True, single=True), "biography": T("identity", "Publicly documented biographical note"),
    "national_id_ref": T("identity", "Identity-document or SSN reference (token only)", reference=True),
    "email": T("contact", "Email address", identifier="email"), "username": T("online_footprint", "Username or handle", identifier="username"), "phone": T("contact", "Phone number", restricted=True),
    "business_contact": T("contact", "Published business contact point", claim="professional_contact"),
    "place": T("locations", "General place", claim="location_public", sensitivity="RESTRICTED"), "location_history": T("locations", "Location history entry", restricted=True),
    "residential_address": T("locations", "Residential address", restricted=True, single=True),
    "institution": T("education", "Institution", claim="education"), "qualification": T("education", "Qualification"), "attendance_period": T("education", "Attendance period"),
    "publication": T("education", "Publication", claim="publication"),
    "employer": T("employment", "Employer", claim="employer"), "position": T("employment", "Position", claim="role"), "association": T("employment", "Professional association", claim="business_association"),
    "profile_url": T("online_footprint", "Social, developer, forum or gaming profile", identifier="url"), "website": T("online_footprint", "Website", identifier="url"),
    "archived_profile": T("online_footprint", "Archived profile page"), "repository": T("online_footprint", "Public code repository"),
    "organization": T("business", "Organization affiliation", identifier="organization"), "filing": T("business", "Public filing or registration"), "owned_domain": T("business", "Owned or authorized domain", identifier="domain"),
    "device": T("devices", "Authorized device or asset"),
    "document": T("images_documents", "Document reference", claim="document"),
    "relationship": T("relationships", "Evidence-backed professional or organizational connection"),
    "custom": T("custom", "Custom attribute"),
}
LEAD_TYPES = {"name": "full_name", "url": "profile_url", "username": "username", "employer": "employer", "role": "position", "location": "place"}
_PHONE = re.compile(r"^\+?[0-9][0-9 ()\-.]{5,22}[0-9]$")
_DATE = re.compile(r"^\d{4}(-\d{2}(-\d{2})?)?$")


def _now() -> datetime:
    return datetime.now(UTC)


def _cat(it: ProfileItem) -> str:
    """The category an item is shown under: its type's own, so a reclassified or corrected item moves with its type."""
    return str(TYPES.get(it.type, TYPES["custom"])["category"]) if it.type != "custom" else it.category


def _aware(d: datetime | None) -> datetime | None:
    return d if d is None or d.tzinfo else d.replace(tzinfo=UTC)


def type_catalog() -> list[dict[str, Any]]:
    return [{"type": k, "category": v["category"], "label": v["label"], "restricted": v["restricted"], "reference_only": v["reference"], "single_valued": v["single"],
             "feeds_research": bool(v["identifier"]), "backed_by": "input" if v["identifier"] else "claim" if v["claim"] else "item"} for k, v in TYPES.items()]


# ---- keyed token for reference-only values --------------------------------------------------------------------------------------------------
def _token(db: Session, value: str) -> str:
    row = db.get(Setting, "profile_ref_key")
    if row is None:
        row = Setting(key="profile_ref_key", value_json=secrets.token_hex(32))
        db.add(row)
        db.flush()
    return hmac.new(bytes.fromhex(str(row.value_json)), re.sub(r"[^A-Za-z0-9]", "", value).upper().encode(), hashlib.sha256).hexdigest()


def _mask(t: str, value: str) -> str:
    if t == "phone":
        d = re.sub(r"\D", "", value)
        return f"••• ••• {d[-2:]}" if len(d) >= 4 else "•••"
    if t == "date_of_birth":
        return f"{value[:4]}-••-••" if value[:4].isdigit() else "••••"
    if t in ("residential_address", "location_history"):
        return "••• (restricted location)"
    if t == "national_id_ref":
        d = re.sub(r"[^A-Za-z0-9]", "", value)
        return f"••••{d[-4:]}" if len(d) >= 4 else "••••"
    return "•••"


def _normalize(t: str, value: str) -> tuple[str, str]:
    """(display value, normalized value). Raises ProfileError for a value that does not fit the type."""
    spec = TYPES[t]
    v = " ".join(str(value).split())
    if not v:
        raise ProfileError("invalid_value", "enter a value")
    if len(v) > 600:
        raise ProfileError("invalid_value", "keep the value under 600 characters")
    if spec["identifier"]:
        try:
            n = normalize_identifier(spec["identifier"], v)
        except IdentifierError as exc:
            raise ProfileError("invalid_identifier", str(exc)) from exc
        return n, n.casefold()
    if t == "phone":
        if not _PHONE.match(v):
            raise ProfileError("invalid_value", "enter a phone number such as +1 555 010 1234")
        return v, re.sub(r"\D", "", v)
    if t == "date_of_birth":
        if not _DATE.match(v):
            raise ProfileError("invalid_value", "use YYYY, YYYY-MM or YYYY-MM-DD")
        return v, v
    if t == "national_id_ref":
        if len(re.sub(r"[^A-Za-z0-9]", "", v)) < 4:
            raise ProfileError("invalid_value", "enter the reference as it appears (it is stored only as a non-reversible token and its last four characters)")
        return v, ""                                         # the number itself is never kept; the caller replaces `value` by its masked form
    if t == "archived_profile":
        try:
            u = canonical_url(v)
        except ValueError as exc:
            raise ProfileError("invalid_value", "enter an http(s) URL") from exc
        return u, u.casefold()
    return v, v.casefold()


# ---- policy for restricted values ------------------------------------------------------------------------------------------------------------
def _live_scope(db: Session, subject: Subject) -> str | None:
    st = consent.current_status(db, subject)
    return st.get("consent_id") if st["status"] == "active" else None


def _require_restricted(db: Session, subject: Subject, role: str, need_to_know: str) -> None:
    if role != "owner":
        raise ProfileError("owner_required", "restricted fields can be recorded only by the case owner")
    if _live_scope(db, subject) is None:
        raise ProfileError("authorization_required", "restricted fields need a current, verified authorization for this subject")
    if len(need_to_know.strip()) < 10:
        raise ProfileError("need_to_know_required", "state why this restricted value is needed (at least 10 characters); it is recorded")


# ---- reading ---------------------------------------------------------------------------------------------------------------------------------
def _claim_state(c: ProfileClaim) -> str:
    return {"verified": "corroborated", "subject_confirmed": "candidate", "candidate": "candidate", "conflicting": "conflicting", "rejected": "rejected", "not_assessed": "unassessed"}[c.validation_state]


def _item_type_for_claim(field: str) -> str:
    return {"name": "full_name", "alias": "alias", "handle": "username", "professional_contact": "business_contact", "employer": "employer", "role": "position", "education": "institution",
            "business_association": "association", "owned_domain": "owned_domain", "document": "document", "publication": "publication", "location_public": "place", "other": "custom"}.get(field, "custom")


def sync_existing(db: Session, subject: Subject, actor: str = "system") -> int:
    """Idempotent and read-only for the old tables: every active identifier and every claim gets a master item, once. Nothing is moved, changed or removed."""
    n = 0
    have = {(i.backing_kind, i.backing_id) for i in db.scalars(select(ProfileItem).where(ProfileItem.subject_id == subject.id, ProfileItem.backing_id.is_not(None)))}
    by_kind = {spec["identifier"]: t for t, spec in TYPES.items() if spec["identifier"] and t not in ("website", "owned_domain", "profile_url")}
    by_kind.update({"url": "profile_url", "domain": "owned_domain"})
    scope = _live_scope(db, subject)
    for i in db.scalars(select(SubjectIdentifier).where(SubjectIdentifier.subject_id == subject.id, SubjectIdentifier.status == "active")):
        if ("identifier", i.id) in have:
            continue
        t = by_kind.get(i.kind)
        if t is None:
            continue
        db.add(ProfileItem(subject_id=subject.id, case_id=subject.case_id, category=TYPES[t]["category"], type=t, value=i.value, normalized_value=i.value.casefold(), source_id="subject input",
                           evidence_ids=[i.source_evidence_id] if i.source_evidence_id else [], collection_method="manual", origin="analyst_supplied", recorded_by="existing input",
                           observed_at=i.recorded_at, verification_state="unassessed", sensitivity="INTERNAL", scope_id=scope, is_input=True, backing_kind="identifier", backing_id=i.id,
                           retention_policy={"days": subject.retention_days}))
        n += 1
    for c in db.scalars(select(ProfileClaim).where(ProfileClaim.subject_id == subject.id)):
        if ("claim", c.id) in have:
            continue
        t = _item_type_for_claim(c.field)
        sv = c.structured_value
        text = str(sv.get("text") if isinstance(sv, dict) and "text" in sv else json.dumps(sv, sort_keys=True))[:600]
        db.add(ProfileItem(subject_id=subject.id, case_id=subject.case_id, category=TYPES[t]["category"], type=t, value=text, normalized_value=text.casefold()[:600], attributes={"claim_field": c.field},
                           source_id="profile claim", evidence_ids=list(c.evidence_ids), collection_method="manual", origin="subject_provided" if c.assertion_source == "subject" else "analyst_supplied",
                           recorded_by=c.reviewer or "existing claim", observed_at=c.observed_from, last_verified_at=c.reviewed_at, verification_state=_claim_state(c),
                           self_attested=c.validation_state == "subject_confirmed", sensitivity=c.sensitivity, scope_id=scope, backing_kind="claim", backing_id=c.id,
                           retention_policy={"days": subject.retention_days}))
        n += 1
    db.flush()
    return n


_HANDLE = re.compile(r"^@?[A-Za-z0-9][A-Za-z0-9_.\-]{1,38}$")
_CODE_HOSTS = ("github.com", "gitlab.com", "bitbucket.org", "codeberg.org", "sr.ht")


def classify_lead(kind: str, raw: str, via: str = "") -> tuple[str | None, str]:
    """(item type, why) for a value a source showed next to an address. A git author name or profile name that is one handle-shaped token is a HANDLE, not a person's name,
    and a repository link is not a profile link. The raw value and the source's own label are kept either way."""
    t = LEAD_TYPES.get(kind)
    v = raw.strip()
    if kind == "name" and v and " " not in v and _HANDLE.match(v):
        low = v.lstrip("@")
        if low == low.lower() or any(c in low for c in "_-.0123456789") or low.casefold() == via.casefold():
            return "username", "one handle-shaped word with no spaces: treated as an account handle, not a legal name (the source's own label was 'name')"
    if kind == "url":
        try:
            u = urlsplit(canonical_url(v))
        except ValueError:
            return t, ""
        parts = [x for x in u.path.split("/") if x]
        if (u.hostname or "") in _CODE_HOSTS and len(parts) >= 2:
            return "repository", "a repository page, not the person's profile page"
    return t, ""


def repair_lead_types(db: Session, subject: Subject) -> int:
    """Items an earlier version typed wrongly (a handle as a full name, a repository as a profile link) are corrected once, with the original kept and the change reversible.
    Only untouched discovered candidates are changed: anything a person has reviewed or edited is left alone."""
    n = 0
    for it in db.scalars(select(ProfileItem).where(ProfileItem.subject_id == subject.id, ProfileItem.origin == "discovered", ProfileItem.status == "active", ProfileItem.verification_state == "candidate")):
        if "classification" in it.attributes or it.type not in ("full_name", "profile_url"):
            continue
        kind = "name" if it.type == "full_name" else "url"
        want, why = classify_lead(kind, it.value, str(it.attributes.get("via", "")))
        if want and want != it.type and why:
            _retype(db, it, want, actor="system", reason="automatic correction: " + why, automatic=True)
            n += 1
    return n


def _retype(db: Session, it: ProfileItem, to_type: str, *, actor: str, reason: str, automatic: bool = False) -> None:
    disp, norm = _normalize(to_type, it.value)
    cls = dict(it.attributes.get("classification") or {})
    hist = list(cls.get("history") or [])
    if not hist:
        cls["original"] = {"type": it.type, "category": _cat(it), "automatic": True}
    hist.append({"from": it.type, "to": to_type, "by": actor, "reason": reason[:300], "at": _now().isoformat(), "automatic": automatic, "value": it.value})
    cls["history"] = hist
    it.attributes = {**it.attributes, "classification": cls}
    it.type, it.category, it.value, it.normalized_value = to_type, TYPES[to_type]["category"], disp, norm
    it.version += 1
    it.updated_at = _now()
    audit.record(db, "profile.item_reclassify", actor=actor, case_id=it.case_id, resource_type="profile_item", resource_id=it.id, metadata={"from": hist[-1]["from"], "to": to_type, "automatic": automatic})


def preview_reclassify(db: Session, subject: Subject, item_id: str, to_type: str) -> dict[str, Any]:
    it = _get(db, subject, item_id)
    _check_reclassify(it, to_type)
    disp, norm = _normalize(to_type, it.value)
    return {"item": f"item:{it.id}", "from_type": it.type, "to_type": to_type, "from_category": _cat(it), "to_category": TYPES[to_type]["category"], "value": disp, "normalized_value": norm,
            "effects": [f"Moves from {_cat(it).replace('_', ' ')} to {TYPES[to_type]['category'].replace('_', ' ')}.", "The extracted value, source, evidence and dates are unchanged.",
                        "The verification state and confidence are unchanged: retyping is not verification.", "The earlier type stays in the history and the change can be undone."],
            "feeds_research": False}


def _check_reclassify(it: ProfileItem, to_type: str) -> None:
    if to_type not in TYPES or to_type == "custom":
        raise ProfileError("invalid_type", "choose a type from the catalog")
    a, b = TYPES.get(it.type, TYPES["custom"]), TYPES[to_type]
    if a["restricted"] or b["restricted"] or a["reference"] or b["reference"]:
        raise ProfileError("restricted_type", "restricted types cannot be created by reclassifying")
    if it.backing_kind is not None or it.is_input:
        raise ProfileError("backed_item_fixed", "an input or a reviewed claim keeps its type: add it again with the right type and retire this one, so research history stays attached")
    if it.type == to_type:
        raise ProfileError("same_type", "that is already its type")


def reclassify(db: Session, subject: Subject, item_id: str, *, to_type: str, role: str, actor: str, reason: str) -> ProfileItem:
    if role == "viewer":
        raise ProfileError("forbidden", "viewers cannot reclassify items")
    if len(reason.strip()) < 5:
        raise ProfileError("reason_required", "say why the type is wrong (a few words)")
    it = _get(db, subject, item_id)
    _check_reclassify(it, to_type)
    _retype(db, it, to_type, actor=actor, reason=reason.strip())
    return it


def undo_reclassify(db: Session, subject: Subject, item_id: str, *, role: str, actor: str) -> ProfileItem:
    if role == "viewer":
        raise ProfileError("forbidden", "viewers cannot reclassify items")
    it = _get(db, subject, item_id)
    hist = list((it.attributes.get("classification") or {}).get("history") or [])
    if not hist:
        raise ProfileError("nothing_to_undo", "this item has never been reclassified")
    last = hist[-1]
    if last["to"] != it.type:
        raise ProfileError("changed_since", "the type was changed again; undo the later change first")
    cls = dict(it.attributes["classification"])
    cls["history"] = hist[:-1]
    cls["locked"] = True                                      # an undone correction is not applied again automatically
    disp, norm = _normalize(last["from"], it.value)
    it.type, it.category, it.value, it.normalized_value = last["from"], TYPES[last["from"]]["category"], disp, norm
    it.attributes = {**it.attributes, "classification": cls}
    it.version += 1
    it.updated_at = _now()
    audit.record(db, "profile.item_reclassify_undo", actor=actor, case_id=subject.case_id, resource_type="profile_item", resource_id=it.id, metadata={"from": last["to"], "to": last["from"]})
    return it


def sweep_leads(db: Session, subject: Subject, actor: str = "system") -> int:
    """Turn cited exact-email references into candidate items. A lead is a CANDIDATE: never an input, never a fact."""
    runs = {t.run_id: t for t in db.scalars(select(ResearchTask).where(ResearchTask.subject_id == subject.id)) if t.run_id}
    scope = _live_scope(db, subject)
    n = 0
    for f in db.scalars(select(Finding).where(Finding.case_id == subject.case_id, Finding.predicate == "email.reference")):
        if f.run_id not in runs or not isinstance(f.value_json, dict):
            continue
        v = f.value_json
        for kind, vals in (v.get("leads") or {}).items():
            if kind not in LEAD_TYPES:
                continue
            for raw in vals:
                t, why = classify_lead(kind, raw, str((v.get("leads") or {}).get("username", [""])[0] if (v.get("leads") or {}).get("username") else ""))
                if t is None:
                    continue
                try:
                    disp, norm = _normalize(t, raw)
                except ProfileError:
                    continue
                if not norm or db.scalars(select(ProfileItem).where(ProfileItem.subject_id == subject.id, ProfileItem.type == t, ProfileItem.normalized_value == norm,
                                                                    ProfileItem.status == "active")).first():
                    continue
                db.add(ProfileItem(subject_id=subject.id, case_id=subject.case_id, category=TYPES[t]["category"], type=t, value=disp, normalized_value=norm, source_id=str(v.get("source") or f.adapter_id),
                                   evidence_ids=[f.evidence_id], collection_method=f"adapter:{f.adapter_id}", origin="discovered", recorded_by=actor, observed_at=f.observed_at, confidence=f.confidence,
                                   verification_state="candidate", sensitivity=TYPES[t]["sensitivity"], scope_id=scope, attributes={"match": v.get("match", ""), "via": v.get("via_kind", ""),
                                                                                                                                      "reason": f.confidence_reason, "reference": v.get("url", ""), "label_from_source": kind,
                                                                                                                                      **({"classification": {"original": {"type": LEAD_TYPES[kind], "automatic": True}, "basis": why, "history": [{"from": LEAD_TYPES[kind], "to": t, "by": "system", "automatic": True, "reason": why, "at": _now().isoformat(), "value": disp}]}} if why else {})},
                                   retention_policy={"days": subject.retention_days}))
                n += 1
    db.flush()
    return n


def _effective_state(db: Session, it: ProfileItem) -> str:
    if it.backing_kind == "claim" and it.backing_id:
        c = db.get(ProfileClaim, it.backing_id)
        if c:
            return _claim_state(c)
    return it.verification_state


def _conflicts(db: Session, subject: Subject) -> set[str]:
    """Ids of items that disagree with another live item of a single-valued type. Both sides are kept."""
    out: set[str] = set()
    for t, spec in TYPES.items():
        if not spec["single"]:
            continue
        rows = [r for r in db.scalars(select(ProfileItem).where(ProfileItem.subject_id == subject.id, ProfileItem.type == t, ProfileItem.status == "active"))
                if r.verification_state != "rejected"]
        if len({r.normalized_value or r.value for r in rows}) > 1:
            out |= {r.id for r in rows}
    return out


def item_dict(db: Session, it: ProfileItem, *, role: str, conflicting: bool = False, revealed: bool = False) -> dict[str, Any]:
    spec = TYPES.get(it.type, TYPES["custom"])
    state = "conflicting" if conflicting and it.verification_state not in ("rejected",) else _effective_state(db, it)
    restricted = spec["restricted"]
    shown = it.value if (not restricted or revealed) else _mask(it.type, it.value)
    ev = []
    for eid in it.evidence_ids:
        e = db.get(Evidence, eid)
        if e:
            ev.append({"id": e.id, "title": e.title, "kind": e.kind, "sha256": e.sha256, "url": e.original_url})
    return {"id": f"item:{it.id}", "category": _cat(it), "type": it.type, "type_label": spec["label"], "custom_type": it.custom_type, "value": shown, "masked": restricted and not revealed,
            "restricted": restricted, "normalized_value": "" if restricted else it.normalized_value, "attributes": {} if restricted else it.attributes, "source_id": it.source_id, "evidence": ev,
            "collection_method": it.collection_method, "origin": it.origin, "recorded_by": it.recorded_by, "observed_at": it.observed_at, "last_verified_at": it.last_verified_at,
            "confidence": it.confidence, "verification_state": state, "state_label": STATE_LABEL[state], "self_attested": it.self_attested, "sensitivity": it.sensitivity, "scope_id": it.scope_id,
            "retention_policy": it.retention_policy, "is_input": it.is_input, "feeds_research": bool(spec["identifier"]) and it.is_input and it.status == "active", "backed_by": it.backing_kind or "item",
            "merged_into": it.merged_into, "version": it.version, "note": it.note, "discovered": it.origin == "discovered", "reference_only": spec["reference"], "created_at": it.created_at,
            "caveat": "Self-attested: the subject's own statement is not independent corroboration." if it.self_attested else ""}


def _mirrors(db: Session, st: Any, subject: Subject, role: str) -> dict[str, list[dict[str, Any]]]:
    """Entries owned by other stores, shown read-only with their own state. Opening one goes to its own tab."""
    out: dict[str, list[dict[str, Any]]] = {"contact": [], "online_footprint": [], "images_documents": [], "security_exposure": []}
    for e in emails.list_for(db, st, subject, role=role)["items"]:
        out["contact"].append({"id": f"email:{e['id']}", "category": "contact", "type": "associated_email", "type_label": "Associated email (candidate)", "value": e["address"], "masked": e["masked"],
                               "restricted": False, "verification_state": ("self_attested" if e["classification"] == "confirmed" and e.get("confirmation_kind") != "independently_corroborated"
                                                                            else "corroborated" if e["classification"] == "confirmed" else "candidate" if e["classification"] in ("likely", "possible") else "rejected"),
                               "state_label": e["label"], "evidence": e["evidence"], "origin": "discovered", "readonly": True, "open": "Associated emails", "note": "; ".join(e["explanation"])[:200],
                               "is_input": e["is_input"], "feeds_research": e["is_input"], "confidence": "unknown", "caveat": ""})
    for c in db.scalars(select(ProfileCandidateLink).where(ProfileCandidateLink.subject_id == subject.id)):
        own = candidates.ownership(db, c)
        st_ = {"confirmed": "self_attested" if own != "independently_corroborated" else "corroborated", "rejected": "rejected", "candidate": "candidate", "unsure": "candidate"}[c.state]
        out["online_footprint"].append({"id": f"account:{c.id}", "category": "online_footprint", "type": "account_candidate", "type_label": "Public account (review queue)", "value": c.canonical_url,
                                        "masked": False, "restricted": False, "verification_state": st_, "state_label": STATE_LABEL[st_], "evidence": evidence_refs(db, c.evidence_ids), "origin": "discovered", "readonly": True,
                                        "open": "Review queue", "note": c.hypothesis, "is_input": False, "feeds_research": False, "confidence": "unknown", "caveat": "A handle that exists is not the person."})
    if role != "viewer":
        from . import images as pimages
        for a in db.scalars(select(ImageAsset).where(ImageAsset.subject_id == subject.id)):
            out["images_documents"].append({"id": f"image:{a.id}", "category": "images_documents", "type": "image", "type_label": "Image", "value": f"image {a.id[:8]}", "masked": False, "restricted": False,
                                            "verification_state": "unassessed", "state_label": STATE_LABEL["unassessed"], "evidence": [], "origin": "analyst_supplied", "readonly": True, "open": "Images",
                                            "note": "Provenance: the imported file and its hashes. Reverse-image providers are manual link-outs; a similar image is not an identification.",
                                            "is_input": False, "feeds_research": False, "confidence": "unknown", "caveat": pimages.LIMITS})
        for x in db.scalars(select(ExposureIndicator).where(ExposureIndicator.subject_id == subject.id)):
            st_ = {"confirmed_exposure": "corroborated", "not_found_in_checked_sources": "not_available", "not_assessed": "unassessed"}[x.status]
            out["security_exposure"].append({"id": f"exposure:{x.id}", "category": "security_exposure", "type": "exposure_indicator", "type_label": x.cls.replace("_", " "),
                                             "value": x.masked_descriptor or x.cls, "masked": False, "restricted": False, "verification_state": st_, "state_label": x.status.replace("_", " "),
                                             "evidence": [], "origin": "verified_provider" if x.provider != "manual" else "analyst_supplied", "readonly": True, "open": "Exposure",
                                             "note": f"{x.provider}; status {x.status.replace('_', ' ')}", "is_input": False, "feeds_research": False, "confidence": "unknown",
                                             "caveat": "'Not found in checked sources' describes only the sources that were checked."})
    return out


def _asset_cover(db: Session, subject: Subject, host: str) -> dict[str, Any]:
    """Whether an inventoried device is inside a live asset authorization of this case. The inventory itself never causes a request: verification needs its own approved plan."""
    from ..aiv import policy as aivp
    from ..db.models import AssetAuthorization
    h = host.strip().lower()
    now = _now()
    for a in db.scalars(select(AssetAuthorization).where(AssetAuthorization.case_id == subject.case_id)):
        if aivp.authorization_live(a, now) and any(h == str(x).lower() or (str(x).startswith("*.") and h.endswith(str(x)[1:])) for x in (a.canonical_scope or [])):
            return {"covered": True, "reason": "This host is named by a live asset authorization. Checks still need an approved plan in the Verification tab."}
    return {"covered": False, "reason": "No live asset authorization names this host, so it cannot be checked. An inventory entry is not permission to test it."}


def sections(db: Session, st: Any, subject: Subject, *, role: str, state: str | None = None, q: str | None = None) -> dict[str, Any]:
    sync_existing(db, subject)
    repair_lead_types(db, subject)
    sweep_leads(db, subject)
    conflicts = _conflicts(db, subject)
    mirrors = _mirrors(db, st, subject, role)
    rows = list(db.scalars(select(ProfileItem).where(ProfileItem.subject_id == subject.id, ProfileItem.status == "active", ProfileItem.merged_into.is_(None)).order_by(ProfileItem.created_at)))
    hidden = 0
    out = []
    for key, title in CATEGORIES:
        items: list[dict[str, Any]] = []
        for it in rows:
            if _cat(it) != key:
                continue
            if TYPES.get(it.type, TYPES["custom"])["restricted"] and role == "viewer":
                hidden += 1
                continue
            items.append(item_dict(db, it, role=role, conflicting=it.id in conflicts))
        items += mirrors.get(key, [])
        if key == "devices":
            for i in items:
                i["asset_authorization"] = _asset_cover(db, subject, str(i.get("attributes", {}).get("hostname") or i.get("value") or ""))
        if key == "timeline":
            from . import timeline
            items = [{"id": f"timeline:{i}", "category": "timeline", "type": e["kind"], "type_label": e["kind"], "value": e["text"], "masked": False, "restricted": False, "verification_state": "unassessed",
                      "state_label": e["basis"], "evidence": [{"id": x} for x in e["evidence_ids"]], "origin": "system", "readonly": True, "observed_at": e["at"], "is_input": False, "feeds_research": False,
                      "confidence": "unknown", "caveat": "", "note": ""} for i, e in enumerate(timeline.build(db, subject, include_restricted=role != "viewer")[-40:])]
        if state:
            items = [i for i in items if i["verification_state"] == state]
        if q:
            items = [i for i in items if q.casefold() in str(i.get("value", "")).casefold() or q.casefold() in str(i.get("type_label", "")).casefold()]
        counts = {s: sum(1 for i in items if i["verification_state"] == s) for s in DISPLAY_STATES}
        out.append({"key": key, "title": title, "items": items, "counts": counts, "types": [t["type"] for t in type_catalog() if t["category"] == key],
                    "empty_note": "Not researched. An empty section is unknown, never evidence that nothing exists." if not items else ""})
    return {"subject_id": subject.id, "role": role, "sections": out, "restricted_hidden": hidden, "states": [{"key": s, "label": STATE_LABEL[s]} for s in DISPLAY_STATES],
            "notice": "Inputs are what you provided; claims are what evidence supports. An empty field means not researched. Coverage describes attempted authorized methods only.",
            "types": type_catalog(), "restricted_note": RESTRICTED_NOTE}


# ---- writing ---------------------------------------------------------------------------------------------------------------------------------
def _check_evidence(db: Session, subject: Subject, ids: list[str]) -> list[str]:
    out = []
    for eid in dict.fromkeys(ids):
        ev = db.get(Evidence, eid)
        if not ev or ev.case_id != subject.case_id:
            raise ProfileError("evidence_not_in_case", f"evidence {eid} is not in this case")
        out.append(eid)
    return out


def add_item(db: Session, subject: Subject, *, type: str, value: str, role: str, actor: str, origin: str = "analyst_supplied", evidence_ids: list[str] | None = None, source_id: str = "",
             attributes: dict[str, Any] | None = None, observed_at: datetime | None = None, confidence: str = "unknown", custom_type: str = "", note: str = "", need_to_know: str = "",
             collection_method: str = "manual") -> tuple[ProfileItem, bool]:
    """Returns (item, created). Adding the same value again attaches the new evidence to the existing item instead of duplicating it (idempotent)."""
    if type not in TYPES:
        raise ProfileError("invalid_type", f"type must be one of {', '.join(TYPES)}")
    if origin not in ORIGINS:
        raise ProfileError("invalid_origin", f"origin must be one of {', '.join(ORIGINS)}")
    if confidence not in ("unknown", "low", "medium", "high"):
        raise ProfileError("invalid_confidence", "confidence must be unknown, low, medium or high")
    spec = TYPES[type]
    if type == "custom" and not custom_type.strip():
        raise ProfileError("custom_type_required", "name the custom attribute type")
    if type == "relationship" and not (evidence_ids or []):
        raise ProfileError("evidence_required", "a relationship must cite evidence; inferred personal relationships are not recorded as facts")
    ev = _check_evidence(db, subject, evidence_ids or [])
    if spec["restricted"]:
        _require_restricted(db, subject, role, need_to_know)
    elif role == "viewer":
        raise ProfileError("forbidden", "viewers cannot edit the profile")
    disp, norm = _normalize(type, value)
    token = None
    if spec["reference"]:
        token = _token(db, value)
        disp, norm = _mask(type, value), f"ref:{token[:16]}"
    dup = db.scalars(select(ProfileItem).where(ProfileItem.subject_id == subject.id, ProfileItem.type == type, ProfileItem.normalized_value == norm, ProfileItem.status == "active",
                                                 ProfileItem.merged_into.is_(None))).first() if norm else None
    if dup is not None:
        dup.evidence_ids = list(dict.fromkeys([*dup.evidence_ids, *ev]))
        if origin == "subject_provided" and dup.origin != "subject_provided" and dup.verification_state in ("unassessed", "candidate"):
            dup.self_attested = dup.self_attested or origin == "subject_provided"
        dup.updated_at = _now()
        return dup, False
    scope = _live_scope(db, subject)
    it = ProfileItem(subject_id=subject.id, case_id=subject.case_id, category=spec["category"], type=type, custom_type=custom_type.strip()[:60], value=disp, normalized_value=norm,
                     attributes=dict(attributes or {}), source_id=(source_id or ("subject statement" if origin == "subject_provided" else "analyst entry"))[:80], evidence_ids=ev,
                     collection_method=collection_method, origin=origin, recorded_by=actor, observed_at=observed_at, confidence=confidence,
                     verification_state="unassessed" if spec["identifier"] else "candidate", self_attested=origin == "subject_provided", sensitivity=spec["sensitivity"], scope_id=scope,
                     retention_policy={"days": subject.retention_days}, note=" ".join(note.split())[:1000], reference_token=token)
    if spec["identifier"]:
        ident = add_identifier(db, subject, spec["identifier"], disp, actor=actor, source_evidence_id=ev[0] if ev else None)
        it.is_input, it.backing_kind, it.backing_id = True, "identifier", ident.id
        existing = db.scalars(select(ProfileItem).where(ProfileItem.backing_kind == "identifier", ProfileItem.backing_id == ident.id, ProfileItem.status == "active")).first()
        if existing is not None:
            existing.evidence_ids = list(dict.fromkeys([*existing.evidence_ids, *ev]))
            return existing, False
    elif spec["claim"]:
        c = add_claim(db, subject, field=spec["claim"], value=disp, evidence_ids=ev, assertion_source="subject" if origin == "subject_provided" else "analyst", actor=actor,
                      observed_from=observed_at)
        it.backing_kind, it.backing_id = "claim", c.id
    db.add(it)
    db.flush()
    audit.record(db, "profile.item_add", actor=actor, case_id=subject.case_id, resource_type="profile_item", resource_id=it.id,
                 metadata={"type": type, "category": spec["category"], "restricted": spec["restricted"], "origin": origin, "need_to_know": bool(need_to_know)})
    return it, True


def _get(db: Session, subject: Subject, item_id: str) -> ProfileItem:
    iid = item_id.removeprefix("item:")
    it = db.get(ProfileItem, iid)
    if not it or it.subject_id != subject.id or it.status == "retired":
        raise ProfileError("not_found", "item not found")
    return it


def edit_item(db: Session, subject: Subject, item_id: str, *, role: str, actor: str, value: str | None = None, note: str | None = None, attributes: dict[str, Any] | None = None,
              confidence: str | None = None, observed_at: datetime | None = None, evidence_ids: list[str] | None = None) -> ProfileItem:
    it = _get(db, subject, item_id)
    spec = TYPES.get(it.type, TYPES["custom"])
    if role == "viewer" or (spec["restricted"] and role != "owner"):
        raise ProfileError("forbidden", "you cannot edit this item")
    if it.backing_kind == "identifier" and value is not None:
        raise ProfileError("input_value_fixed", "an input's value cannot be edited: add the corrected value and reject or remove this one, so research history stays attached to what was searched")
    if value is not None and not spec["reference"]:
        disp, norm = _normalize(it.type, value)
        it.value, it.normalized_value = disp, norm
        it.version += 1
        if it.backing_kind == "claim" and it.backing_id and (c := db.get(ProfileClaim, it.backing_id)):
            c.structured_value = {"text": disp}
    if note is not None:
        it.note = " ".join(note.split())[:1000]
    if attributes is not None:
        it.attributes = {**it.attributes, **attributes}
    if confidence is not None:
        if confidence not in ("unknown", "low", "medium", "high"):
            raise ProfileError("invalid_confidence", "confidence must be unknown, low, medium or high")
        it.confidence = confidence
    if observed_at is not None:
        it.observed_at = observed_at
    if evidence_ids:
        it.evidence_ids = list(dict.fromkeys([*it.evidence_ids, *_check_evidence(db, subject, evidence_ids)]))
    it.updated_at = _now()
    audit.record(db, "profile.item_edit", actor=actor, case_id=subject.case_id, resource_type="profile_item", resource_id=it.id, metadata={"type": it.type})
    return it


def set_state(db: Session, subject: Subject, item_id: str, *, to_state: str, role: str, actor: str, basis: str, evidence_ids: list[str] | None = None, independent: bool = False) -> ProfileItem:
    """Confirm, reject, mark conflicting, needs-review (candidate) or not-available. Corroboration needs independent evidence; a self-attestation is recorded as one and stays a candidate."""
    if to_state not in STATES:
        raise ProfileError("invalid_state", f"state must be one of {', '.join(STATES)}")
    if role == "viewer":
        raise ProfileError("forbidden", "viewers cannot change verification states")
    if not basis.strip():
        raise ProfileError("basis_required", "record the reason or method for this decision")
    it = _get(db, subject, item_id)
    if TYPES.get(it.type, TYPES["custom"])["restricted"] and role != "owner":
        raise ProfileError("forbidden", "only the case owner can decide on restricted fields")
    ev = list(dict.fromkeys([*it.evidence_ids, *_check_evidence(db, subject, evidence_ids or [])]))
    prev = _effective_state(db, it)
    if to_state == "corroborated":
        if not ev:
            raise ProfileError("evidence_required", "corroboration needs cited evidence")
        if not independent:
            it.self_attested = True
            it.verification_state = "candidate"
            it.last_verified_at = _now()
            it.evidence_ids = ev
            db.add(ProfileReviewEvent(subject_id=subject.id, case_id=subject.case_id, target_type="item", target_id=it.id, from_state=prev, to_state="candidate", reviewer=actor,
                                      basis=f"self-attestation recorded, not corroboration: {basis.strip()}"[:900], attestation="subject", evidence_ids=ev))
            audit.record(db, "profile.item_state", actor=actor, case_id=subject.case_id, resource_type="profile_item", resource_id=it.id, metadata={"from": prev, "to": "candidate", "self_attested": True})
            raise ProfileError("self_attestation_only", "recorded as self-attested: it stays a candidate. Corroboration needs evidence from a source independent of the subject's own statement")
    it.evidence_ids = ev
    it.verification_state = to_state
    it.last_verified_at = _now()
    it.self_attested = False if to_state == "corroborated" else it.self_attested
    if it.backing_kind == "claim" and it.backing_id and to_state in ("corroborated", "rejected", "conflicting", "candidate"):
        review_claim(db, subject, it.backing_id, to_state={"corroborated": "verified", "rejected": "rejected", "conflicting": "conflicting", "candidate": "candidate"}[to_state],
                     reviewer=actor, basis=basis, evidence_ids=ev)
    if it.backing_kind == "identifier" and it.backing_id and to_state == "rejected":
        remove_identifier(db, subject, it.backing_id, actor)               # a rejected input stops feeding research
        it.is_input = False
    db.add(ProfileReviewEvent(subject_id=subject.id, case_id=subject.case_id, target_type="item", target_id=it.id, from_state=prev, to_state=to_state, reviewer=actor, basis=basis.strip(),
                              attestation="corroborated" if to_state == "corroborated" else "none", evidence_ids=ev))
    audit.record(db, "profile.item_state", actor=actor, case_id=subject.case_id, resource_type="profile_item", resource_id=it.id, metadata={"from": prev, "to": to_state})
    return it


def retire_item(db: Session, subject: Subject, item_id: str, *, role: str, actor: str) -> ProfileItem:
    it = _get(db, subject, item_id)
    if role == "viewer" or (TYPES.get(it.type, TYPES["custom"])["restricted"] and role != "owner"):
        raise ProfileError("forbidden", "you cannot remove this item")
    if it.backing_kind == "identifier" and it.backing_id:
        remove_identifier(db, subject, it.backing_id, actor)
    if it.backing_kind == "claim" and it.backing_id:
        review_claim(db, subject, it.backing_id, to_state="rejected", reviewer=actor, basis="removed from the profile editor")
    it.status, it.is_input = "retired", False
    audit.record(db, "profile.item_retire", actor=actor, case_id=subject.case_id, resource_type="profile_item", resource_id=it.id)
    return it


def promote_to_input(db: Session, subject: Subject, item_id: str, *, role: str, actor: str, basis: str) -> ProfileItem:
    """A discovered candidate becomes an input only by a person's decision, and only for a type the planner can research. Authorization still decides what runs."""
    it = _get(db, subject, item_id)
    spec = TYPES.get(it.type, TYPES["custom"])
    if role == "viewer":
        raise ProfileError("forbidden", "viewers cannot change inputs")
    if not spec["identifier"]:
        raise ProfileError("not_an_input_type", "this kind of fact is not used as a research input")
    if it.is_input:
        return it
    if it.verification_state != "corroborated" and not basis.strip():
        raise ProfileError("basis_required", "say why this discovered value belongs to the subject")
    ident = add_identifier(db, subject, spec["identifier"], it.normalized_value if spec["identifier"] not in ("name", "organization") else it.value, actor=actor,
                           source_evidence_id=it.evidence_ids[0] if it.evidence_ids else None)
    it.is_input, it.backing_kind, it.backing_id = True, "identifier", ident.id
    db.add(ProfileReviewEvent(subject_id=subject.id, case_id=subject.case_id, target_type="item", target_id=it.id, from_state="discovered", to_state="input", reviewer=actor, basis=basis.strip()[:900]))
    audit.record(db, "profile.item_promote", actor=actor, case_id=subject.case_id, resource_type="profile_item", resource_id=it.id)
    return it


def reveal(db: Session, subject: Subject, item_id: str, *, role: str, actor: str, reason: str) -> dict[str, Any]:
    it = _get(db, subject, item_id)
    spec = TYPES.get(it.type, TYPES["custom"])
    if not spec["restricted"]:
        raise ProfileError("not_restricted", "this item is not restricted")
    if role != "owner":
        raise ProfileError("owner_required", "only the case owner can reveal a restricted value")
    if spec["reference"]:
        raise ProfileError("reference_only", "this is a reference-only value: the number was never stored, so it cannot be revealed; you can compare a number against it")
    if _live_scope(db, subject) is None:
        raise ProfileError("authorization_required", "revealing needs a current, verified authorization")
    if len(reason.strip()) < 10:
        raise ProfileError("reason_required", "state why you need to see it (at least 10 characters); it is recorded")
    audit.record(db, "profile.item_reveal", actor=actor, case_id=subject.case_id, resource_type="profile_item", resource_id=it.id, metadata={"type": it.type, "reason": reason.strip()[:200]})
    return {"id": f"item:{it.id}", "value": it.value, "notice": "Shown once. It is not copied, exported or indexed."}


def verify_reference(db: Session, subject: Subject, item_id: str, candidate: str, *, role: str, actor: str) -> dict[str, Any]:
    it = _get(db, subject, item_id)
    if not TYPES.get(it.type, TYPES["custom"])["reference"] or not it.reference_token:
        raise ProfileError("not_reference", "this item is not a reference-only value")
    if role not in ("owner", "editor"):
        raise ProfileError("forbidden", "you cannot compare against this value")
    ok = hmac.compare_digest(_token(db, candidate), it.reference_token)
    audit.record(db, "profile.item_compare", actor=actor, case_id=subject.case_id, resource_type="profile_item", resource_id=it.id, metadata={"match": ok})
    return {"match": ok, "note": "Compared by keyed hash; the number you typed was not stored."}


# ---- batch, import, export ----------------------------------------------------------------------------------------------------------------------
MAX_ROWS = 500


def batch_add(db: Session, subject: Subject, rows: list[dict[str, Any]], *, role: str, actor: str) -> dict[str, Any]:
    if len(rows) > MAX_ROWS:
        raise ProfileError("too_many_rows", f"import at most {MAX_ROWS} rows at a time")
    done, errors = [], []
    for i, r in enumerate(rows):
        try:
            with db.begin_nested():                          # a bad row is reported and rolled back on its own; the good rows are kept
                it, created = add_item(db, subject, type=str(r.get("type") or "").strip(), value=str(r.get("value") or ""), role=role, actor=actor, origin=str(r.get("origin") or "analyst_supplied"),
                                       evidence_ids=[e for e in str(r.get("evidence_ids") or "").replace(";", ",").split(",") if e.strip()] if not isinstance(r.get("evidence_ids"), list) else r["evidence_ids"],
                                       source_id=str(r.get("source") or ""), custom_type=str(r.get("custom_type") or ""), note=str(r.get("note") or ""), need_to_know=str(r.get("need_to_know") or ""),
                                       collection_method="import")
                done.append({"row": i + 1, "id": f"item:{it.id}", "created": created})
        except ProfileError as exc:
            errors.append({"row": i + 1, "code": exc.code, "message": exc.message})
    audit.record(db, "profile.items_import", actor=actor, case_id=subject.case_id, resource_type="subject", resource_id=subject.id, metadata={"rows": len(rows), "ok": len(done), "errors": len(errors)})
    return {"rows": len(rows), "created": sum(1 for d in done if d["created"]), "existing": sum(1 for d in done if not d["created"]), "errors": errors}


def parse_import(kind: str, content: str) -> list[dict[str, Any]]:
    try:
        if kind == "csv":
            return list(csv.DictReader(io.StringIO(content)))
        data = json.loads(content)
    except (ValueError, csv.Error) as exc:
        raise ProfileError("unreadable_import", "the file could not be read as that format") from exc
    rows = data if isinstance(data, list) else data.get("items") if isinstance(data, dict) else None
    if not isinstance(rows, list) or not all(isinstance(r, dict) for r in rows):
        raise ProfileError("unreadable_import", "expected a list of objects with type and value")
    return rows


def export(db: Session, st: Any, subject: Subject, *, role: str) -> dict[str, Any]:
    """Redacted by construction: restricted items are omitted (counted), nothing is revealed, and evidence is listed by id and hash only."""
    doc = sections(db, st, subject, role=role)
    out, omitted = [], 0
    for s in doc["sections"]:
        for i in s["items"]:
            if i.get("restricted"):
                omitted += 1
                continue
            out.append({"category": s["key"], "type": i.get("type"), "value": i.get("value"), "state": i["verification_state"], "origin": i.get("origin"), "source": i.get("source_id", ""),
                        "observed_at": i.get("observed_at"), "last_verified_at": i.get("last_verified_at"), "confidence": i.get("confidence"),
                        "evidence": [{"id": e["id"], "sha256": e.get("sha256", "")[:16]} for e in i.get("evidence", [])]})
    audit.record(db, "profile.export", actor="system", case_id=subject.case_id, resource_type="subject", resource_id=subject.id, metadata={"items": len(out), "omitted_restricted": omitted})
    return {"subject": subject.display_name, "generated_at": _now().isoformat(), "items": out, "omitted_restricted": omitted,
            "notice": "Redacted export: restricted values are omitted, evidence is referenced by id and hash. An empty category means not researched."}


# ---- duplicates and reversible merge --------------------------------------------------------------------------------------------------------------
def duplicates(db: Session, subject: Subject) -> list[dict[str, Any]]:
    rows = list(db.scalars(select(ProfileItem).where(ProfileItem.subject_id == subject.id, ProfileItem.status == "active", ProfileItem.merged_into.is_(None))))
    groups: dict[tuple[str, str], list[ProfileItem]] = {}
    for r in rows:
        if TYPES.get(r.type, TYPES["custom"])["restricted"] or not r.normalized_value:
            continue
        key = re.sub(r"[^a-z0-9]", "", r.normalized_value.removeprefix("https://").removeprefix("www."))
        if key:
            groups.setdefault((r.type, key), []).append(r)
    out = []
    for (t, _k), g in groups.items():
        if len(g) > 1:
            out.append({"type": t, "ids": [f"item:{x.id}" for x in g], "values": [x.value for x in g], "reason": "the same value after case, spacing and punctuation are ignored"})
    return out


def merge(db: Session, subject: Subject, keep_id: str, merge_ids: list[str], *, role: str, actor: str, reason: str) -> ProfileItem:
    if role == "viewer":
        raise ProfileError("forbidden", "viewers cannot merge items")
    if not reason.strip():
        raise ProfileError("basis_required", "record why these are the same fact")
    keep = _get(db, subject, keep_id)
    for mid in merge_ids:
        m = _get(db, subject, mid)
        if m.id == keep.id or m.type != keep.type:
            raise ProfileError("merge_conflict", "only items of the same type can be merged")
        if TYPES.get(m.type, TYPES["custom"])["restricted"]:
            raise ProfileError("merge_conflict", "restricted items are not merged automatically")
        keep.evidence_ids = list(dict.fromkeys([*keep.evidence_ids, *m.evidence_ids]))
        m.merged_into, m.status = keep.id, "merged"
        db.add(ProfileReviewEvent(subject_id=subject.id, case_id=subject.case_id, target_type="item", target_id=m.id, from_state="active", to_state="merged", reviewer=actor, basis=reason.strip()[:900],
                                  evidence_ids=m.evidence_ids, reverts_event_id=None))
        if m.backing_kind == "identifier" and m.backing_id and keep.backing_kind != "identifier":
            keep.backing_kind, keep.backing_id, keep.is_input = m.backing_kind, m.backing_id, True
    audit.record(db, "profile.item_merge", actor=actor, case_id=subject.case_id, resource_type="profile_item", resource_id=keep.id, metadata={"merged": len(merge_ids)})
    return keep


def unmerge(db: Session, subject: Subject, item_id: str, *, role: str, actor: str) -> ProfileItem:
    if role == "viewer":
        raise ProfileError("forbidden", "viewers cannot undo merges")
    it = db.get(ProfileItem, item_id.removeprefix("item:"))
    if not it or it.subject_id != subject.id or it.status != "merged" or not it.merged_into:
        raise ProfileError("not_found", "no merged item with that id")
    it.status, it.merged_into = "active", None
    db.add(ProfileReviewEvent(subject_id=subject.id, case_id=subject.case_id, target_type="item", target_id=it.id, from_state="merged", to_state="active", reviewer=actor, basis="merge undone",
                              reverts_event_id=None, bulk_id=str(uuid.uuid4())))
    audit.record(db, "profile.item_unmerge", actor=actor, case_id=subject.case_id, resource_type="profile_item", resource_id=it.id)
    return it
