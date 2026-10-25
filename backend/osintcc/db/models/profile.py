"""Target-profile tables (addendum TP-1.0). Case-scoped, cascade-deleted with the case, stored in the same encrypted database.

Deliberately absent: any column for a plaintext password, session token, recovery secret, full national identifier or face template.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from ..base import Base
from . import pk, ts

SUBJECT_TYPES = ("person", "organization", "domain", "email", "username", "business_record", "image", "document", "imported")
SUBJECT_MODES = ("self", "client", "organization")
CLAIM_STATES = ("verified", "subject_confirmed", "candidate", "conflicting", "rejected", "not_assessed")
CANDIDATE_STATES = ("candidate", "confirmed", "rejected", "unsure")


class Subject(Base):
    __tablename__ = "subjects"
    id: Mapped[str] = pk()
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    type: Mapped[str] = mapped_column(String(24), default="person")
    display_name: Mapped[str] = mapped_column(String(300))
    mode: Mapped[str] = mapped_column(String(16), default="self")  # self | client | organization
    purpose: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(16), default="active")  # active | paused | closed | purged
    owner: Mapped[str | None] = mapped_column(String(80), nullable=True)
    sensitivity: Mapped[str] = mapped_column(String(12), default="RESTRICTED")
    retention_days: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = ts()
    updated_at: Mapped[datetime] = ts()
    __table_args__ = (
        CheckConstraint("mode IN ('self','client','organization')", name="ck_subject_mode"),
        CheckConstraint("status IN ('active','paused','closed','purged')", name="ck_subject_status"),
    )


class SubjectIdentifier(Base):
    __tablename__ = "subject_identifiers"
    id: Mapped[str] = pk()
    subject_id: Mapped[str] = mapped_column(ForeignKey("subjects.id", ondelete="CASCADE"), index=True)
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(16))  # name | alias | username | email | domain | url | organization
    value: Mapped[str] = mapped_column(Text)  # normalized; the database itself is encrypted
    value_hash: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(12), default="active")  # active | removed
    source_evidence_id: Mapped[str | None] = mapped_column(ForeignKey("evidence.id"), nullable=True)
    recorded_at: Mapped[datetime] = ts()
    __table_args__ = (UniqueConstraint("subject_id", "kind", "value_hash", name="uq_subject_identifier"),
                      Index("ix_subject_identifier_hash", "case_id", "value_hash"))


class ProfileClaim(Base):
    __tablename__ = "profile_claims"
    id: Mapped[str] = pk()
    subject_id: Mapped[str] = mapped_column(ForeignKey("subjects.id", ondelete="CASCADE"), index=True)
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    field: Mapped[str] = mapped_column(String(40))
    structured_value: Mapped[Any] = mapped_column(JSON, default=dict)
    sensitivity: Mapped[str] = mapped_column(String(12), default="INTERNAL")
    validation_state: Mapped[str] = mapped_column(String(20), default="candidate")
    observed_from: Mapped[datetime | None] = ts(nullable=True, default=False)
    observed_to: Mapped[datetime | None] = ts(nullable=True, default=False)
    evidence_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    assertion_source: Mapped[str] = mapped_column(String(20), default="analyst")  # analyst | import | workflow | subject
    reviewer: Mapped[str | None] = mapped_column(String(80), nullable=True)
    reviewed_at: Mapped[datetime | None] = ts(nullable=True, default=False)
    reason: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = ts()
    updated_at: Mapped[datetime] = ts()
    __table_args__ = (
        CheckConstraint("validation_state IN ('verified','subject_confirmed','candidate','conflicting','rejected','not_assessed')",
                        name="ck_profile_claim_state"),
        Index("ix_profile_claim_field", "subject_id", "field"),
    )


class ProfileCandidateLink(Base):
    """A hypothesis that a public account/page belongs to the subject. Never a fact until a person decides."""
    __tablename__ = "profile_candidate_links"
    id: Mapped[str] = pk()
    subject_id: Mapped[str] = mapped_column(ForeignKey("subjects.id", ondelete="CASCADE"), index=True)
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    from_identifier_id: Mapped[str | None] = mapped_column(ForeignKey("subject_identifiers.id", ondelete="SET NULL"), nullable=True)
    to_entity_id: Mapped[str | None] = mapped_column(ForeignKey("entities.id", ondelete="SET NULL"), nullable=True)
    cluster_key: Mapped[str] = mapped_column(String(64))  # sha256 of the canonical URL
    canonical_url: Mapped[str] = mapped_column(Text)
    site: Mapped[str] = mapped_column(String(120), default="")
    hypothesis: Mapped[str] = mapped_column(Text, default="")
    adapters: Mapped[list[str]] = mapped_column(JSON, default=list)  # which tools saw it
    source_independence: Mapped[int] = mapped_column(Integer, default=1)  # distinct independent evidence groups
    evidence_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    finding_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    first_seen_at: Mapped[datetime] = ts()
    last_seen_at: Mapped[datetime] = ts()
    state: Mapped[str] = mapped_column(String(12), default="candidate")
    reviewed_by: Mapped[str | None] = mapped_column(String(80), nullable=True)
    reviewed_at: Mapped[datetime | None] = ts(nullable=True, default=False)
    review_basis: Mapped[str] = mapped_column(Text, default="")
    __table_args__ = (
        UniqueConstraint("subject_id", "cluster_key", name="uq_candidate_cluster"),
        CheckConstraint("state IN ('candidate','confirmed','rejected','unsure')", name="ck_candidate_state"),
    )


class ProfileReviewEvent(Base):
    """Append-only history of ownership/validation decisions; reversal writes a new event that restores `from_state`."""
    __tablename__ = "profile_review_events"
    id: Mapped[str] = pk()
    subject_id: Mapped[str] = mapped_column(ForeignKey("subjects.id", ondelete="CASCADE"), index=True)
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    target_type: Mapped[str] = mapped_column(String(12))  # candidate | claim
    target_id: Mapped[str] = mapped_column(String(36))
    from_state: Mapped[str] = mapped_column(String(20))
    to_state: Mapped[str] = mapped_column(String(20))
    reviewer: Mapped[str] = mapped_column(String(80))
    basis: Mapped[str] = mapped_column(Text, default="")
    attestation: Mapped[str] = mapped_column(String(12), default="none")  # none | subject
    evidence_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    bulk_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    reverts_event_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    created_at: Mapped[datetime] = ts()
    __table_args__ = (Index("ix_review_target", "target_type", "target_id", "created_at"),)


class SubjectConsent(Base):
    __tablename__ = "subject_consents"
    id: Mapped[str] = pk()
    subject_id: Mapped[str] = mapped_column(ForeignKey("subjects.id", ondelete="CASCADE"), index=True)
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    mode: Mapped[str] = mapped_column(String(16))
    verification_method: Mapped[str] = mapped_column(String(40))  # self_attestation | signed_document | email_confirmation | in_person | other
    verifier: Mapped[str] = mapped_column(String(200))
    scope_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)  # identities / assets
    source_classes: Mapped[list[str]] = mapped_column(JSON, default=list)
    permitted_purposes: Mapped[list[str]] = mapped_column(JSON, default=list)
    obtained_at: Mapped[datetime] = ts()
    expires_at: Mapped[datetime | None] = ts(nullable=True, default=False)
    revoked_at: Mapped[datetime | None] = ts(nullable=True, default=False)
    revoked_reason: Mapped[str] = mapped_column(Text, default="")
    proof_evidence_id: Mapped[str | None] = mapped_column(ForeignKey("evidence.id"), nullable=True)
    retention_policy: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_by: Mapped[str] = mapped_column(String(80), default="local")
    created_at: Mapped[datetime] = ts()


class ResearchTask(Base):
    __tablename__ = "research_tasks"
    id: Mapped[str] = pk()
    subject_id: Mapped[str] = mapped_column(ForeignKey("subjects.id", ondelete="CASCADE"), index=True)
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    category: Mapped[str] = mapped_column(String(40))
    source_id: Mapped[str] = mapped_column(String(80))
    identifier_id: Mapped[str | None] = mapped_column(ForeignKey("subject_identifiers.id", ondelete="SET NULL"), nullable=True)
    workflow_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    run_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="planned")
    last_attempt: Mapped[datetime | None] = ts(nullable=True, default=False)
    last_success: Mapped[datetime | None] = ts(nullable=True, default=False)
    limitations: Mapped[str] = mapped_column(Text, default="")
    approval_reference: Mapped[str | None] = mapped_column(String(80), nullable=True)
    result_count: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = ts()
    __table_args__ = (Index("ix_research_subject_source", "subject_id", "source_id"),)


class ImageAsset(Base):
    __tablename__ = "image_assets"
    id: Mapped[str] = pk()
    subject_id: Mapped[str] = mapped_column(ForeignKey("subjects.id", ondelete="CASCADE"), index=True)
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    evidence_id: Mapped[str] = mapped_column(ForeignKey("evidence.id"))
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    phash: Mapped[str] = mapped_column(String(16))
    dhash: Mapped[str] = mapped_column(String(16))
    ahash: Mapped[str] = mapped_column(String(16))
    width: Mapped[int] = mapped_column(Integer)
    height: Mapped[int] = mapped_column(Integer)
    format: Mapped[str] = mapped_column(String(12))
    ownership: Mapped[str] = mapped_column(String(16), default="user_owned")  # user_owned | public | authorized
    source_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)  # includes precise GPS when present
    has_gps: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = ts()
    __table_args__ = (UniqueConstraint("subject_id", "sha256", name="uq_image_subject_sha"),)


class ImageMatch(Base):
    __tablename__ = "image_matches"
    id: Mapped[str] = pk()
    asset_id: Mapped[str] = mapped_column(ForeignKey("image_assets.id", ondelete="CASCADE"), index=True)
    subject_id: Mapped[str] = mapped_column(ForeignKey("subjects.id", ondelete="CASCADE"), index=True)
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    other_asset_id: Mapped[str | None] = mapped_column(ForeignKey("image_assets.id", ondelete="CASCADE"), nullable=True)
    match_type: Mapped[str] = mapped_column(String(24))  # exact_duplicate | near_duplicate | possible_crop | provider_page
    provider: Mapped[str | None] = mapped_column(String(40), nullable=True)  # google_lens | bing_visual | tineye | other (manual entry)
    matched_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    distance: Mapped[float | None] = mapped_column(Float, nullable=True)
    score: Mapped[float | None] = mapped_column(Float, nullable=True)
    review_state: Mapped[str] = mapped_column(String(16), default="candidate")  # candidate | confirmed_same_image | rejected | unsure
    reviewer: Mapped[str | None] = mapped_column(String(80), nullable=True)
    note: Mapped[str] = mapped_column(Text, default="")
    evidence_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    observed_at: Mapped[datetime] = ts()


class ExposureIndicator(Base):
    """Status, class, provider and a masked descriptor. There is intentionally no field that could hold a secret or raw dump."""
    __tablename__ = "exposure_indicators"
    id: Mapped[str] = pk()
    subject_id: Mapped[str] = mapped_column(ForeignKey("subjects.id", ondelete="CASCADE"), index=True)
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    cls: Mapped[str] = mapped_column(String(32))
    provider: Mapped[str] = mapped_column(String(60))
    exposure_date: Mapped[datetime | None] = ts(nullable=True, default=False)
    last_checked: Mapped[datetime] = ts()
    status: Mapped[str] = mapped_column(String(32), default="not_assessed")
    risk: Mapped[str] = mapped_column(String(12), default="unknown")
    masked_descriptor: Mapped[str] = mapped_column(String(200), default="")
    verification_basis: Mapped[str] = mapped_column(String(80), default="")
    remediation_state: Mapped[str] = mapped_column(String(16), default="open")
    evidence_id: Mapped[str | None] = mapped_column(ForeignKey("evidence.id"), nullable=True)
    created_at: Mapped[datetime] = ts()
    __table_args__ = (CheckConstraint("status IN ('not_assessed','not_found_in_checked_sources','confirmed_exposure')", name="ck_exposure_status"),)


class RemediationTask(Base):
    __tablename__ = "remediation_tasks"
    id: Mapped[str] = pk()
    subject_id: Mapped[str] = mapped_column(ForeignKey("subjects.id", ondelete="CASCADE"), index=True)
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    indicator_id: Mapped[str | None] = mapped_column(ForeignKey("exposure_indicators.id", ondelete="SET NULL"), nullable=True)
    issue: Mapped[str] = mapped_column(Text)
    priority: Mapped[str] = mapped_column(String(8), default="medium")
    guidance: Mapped[str] = mapped_column(Text, default="")
    owner: Mapped[str | None] = mapped_column(String(80), nullable=True)
    due_at: Mapped[datetime | None] = ts(nullable=True, default=False)
    recheck_at: Mapped[datetime | None] = ts(nullable=True, default=False)
    state: Mapped[str] = mapped_column(String(12), default="open")  # open | in_progress | resolved | wont_fix
    resolution_evidence_id: Mapped[str | None] = mapped_column(ForeignKey("evidence.id"), nullable=True)
    created_at: Mapped[datetime] = ts()
    updated_at: Mapped[datetime] = ts()


class SubjectCorrection(Base):
    __tablename__ = "subject_corrections"
    id: Mapped[str] = pk()
    subject_id: Mapped[str] = mapped_column(ForeignKey("subjects.id", ondelete="CASCADE"), index=True)
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    target_type: Mapped[str] = mapped_column(String(16))
    target_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    request_text: Mapped[str] = mapped_column(Text)
    justification: Mapped[str] = mapped_column(Text, default="")
    requested_by: Mapped[str] = mapped_column(String(200), default="subject")
    status: Mapped[str] = mapped_column(String(12), default="open")  # open | accepted | declined | applied
    resolution: Mapped[str] = mapped_column(Text, default="")
    event_time: Mapped[datetime] = ts()
    audit_seq: Mapped[int | None] = mapped_column(Integer, nullable=True)


class RetentionAction(Base):
    __tablename__ = "retention_actions"
    id: Mapped[str] = pk()
    subject_id: Mapped[str] = mapped_column(String(36), index=True)  # no FK: the record must outlive a purged subject
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    action: Mapped[str] = mapped_column(String(20))  # purge_preview | purge | export | expire
    status: Mapped[str] = mapped_column(String(12), default="done")
    summary_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    performed_by: Mapped[str] = mapped_column(String(80), default="local")
    event_time: Mapped[datetime] = ts()
    audit_seq: Mapped[int | None] = mapped_column(Integer, nullable=True)
