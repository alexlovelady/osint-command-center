"""ORM models (spec sections 6, 21.3, 23.8 — the subset implemented so far)."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from ..base import Base, UTCDateTime, new_id, utcnow


def pk() -> Mapped[str]:
    return mapped_column(String(36), primary_key=True, default=new_id)


def ts(nullable: bool = False, default: bool = True) -> Mapped[datetime]:
    return mapped_column(UTCDateTime(), nullable=nullable, default=utcnow if default else None)


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = pk()
    display_name: Mapped[str] = mapped_column(String(200))
    status: Mapped[str] = mapped_column(String(20), default="active")
    created_at: Mapped[datetime] = ts()


class Case(Base):
    __tablename__ = "cases"
    id: Mapped[str] = pk()
    title: Mapped[str] = mapped_column(String(300))
    description: Mapped[str] = mapped_column(Text, default="")
    category: Mapped[str] = mapped_column(String(50), default="cyber")
    status: Mapped[str] = mapped_column(String(20), default="open")
    purpose: Mapped[str] = mapped_column(Text, default="")
    legal_basis_notes: Mapped[str] = mapped_column(Text, default="")
    scope_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    retention_days: Mapped[int | None] = mapped_column(Integer, nullable=True)
    owner_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = ts()
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, onupdate=utcnow)
    archived_at: Mapped[datetime | None] = ts(nullable=True, default=False)
    __table_args__ = (CheckConstraint("status IN ('open','paused','closed','archived')", name="ck_case_status"),)


class CaseMember(Base):
    __tablename__ = "case_members"
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), primary_key=True)
    access_role: Mapped[str] = mapped_column(String(20), default="owner")  # owner|editor|viewer


class Target(Base):
    __tablename__ = "targets"
    id: Mapped[str] = pk()
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    type: Mapped[str] = mapped_column(String(30))
    raw_input: Mapped[str] = mapped_column(Text)
    canonical_value: Mapped[str] = mapped_column(Text)
    scope_status: Mapped[str] = mapped_column(String(30), default="in_scope")
    owner_or_authority: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = ts()
    __table_args__ = (UniqueConstraint("case_id", "type", "canonical_value", name="uq_target"),)


class Entity(Base):
    """Case-namespaced (privacy by default): never auto-merged across cases."""
    __tablename__ = "entities"
    id: Mapped[str] = pk()
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    type: Mapped[str] = mapped_column(String(30))
    canonical_key: Mapped[str] = mapped_column(Text)
    display_name: Mapped[str] = mapped_column(Text)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    sensitivity: Mapped[str] = mapped_column(String(20), default="INTERNAL")
    first_seen_at: Mapped[datetime] = ts()
    last_seen_at: Mapped[datetime] = ts()
    created_at: Mapped[datetime] = ts()
    __table_args__ = (UniqueConstraint("case_id", "type", "canonical_key", name="uq_entity"),)


class Source(Base):
    __tablename__ = "sources"
    id: Mapped[str] = pk()
    adapter_id: Mapped[str] = mapped_column(String(80))
    source_type: Mapped[str] = mapped_column(String(40), default="http")
    source_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    provider_record_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    retrieved_at: Mapped[datetime] = ts()
    published_at: Mapped[datetime | None] = ts(nullable=True, default=False)
    terms_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    license_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    rate_class: Mapped[str | None] = mapped_column(String(40), nullable=True)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class Evidence(Base):
    __tablename__ = "evidence"
    id: Mapped[str] = pk()
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"))
    source_id: Mapped[str | None] = mapped_column(ForeignKey("sources.id"), nullable=True)
    kind: Mapped[str] = mapped_column(String(40))
    title: Mapped[str] = mapped_column(Text, default="")
    description: Mapped[str] = mapped_column(Text, default="")
    sha256: Mapped[str] = mapped_column(String(64))
    sha512: Mapped[str] = mapped_column(String(128))
    byte_size: Mapped[int] = mapped_column(Integer)
    mime_type: Mapped[str | None] = mapped_column(String(100), nullable=True)
    vault_relpath: Mapped[str | None] = mapped_column(Text, nullable=True)  # None => reference_only
    original_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    retrieved_at: Mapped[datetime] = ts()
    observed_at: Mapped[datetime | None] = ts(nullable=True, default=False)
    published_at: Mapped[datetime | None] = ts(nullable=True, default=False)
    created_by: Mapped[str] = mapped_column(String(80), default="local")
    capture_method: Mapped[str] = mapped_column(String(60), default="adapter")
    sensitivity: Mapped[str] = mapped_column(String(20), default="INTERNAL")
    redacted: Mapped[bool] = mapped_column(Boolean, default=False)
    chain_of_custody_json: Mapped[list[Any]] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = ts()
    __table_args__ = (Index("ix_evidence_case_sha", "case_id", "sha256"),)


class SearchRun(Base):
    __tablename__ = "search_runs"
    id: Mapped[str] = pk()
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"))
    target_id: Mapped[str] = mapped_column(ForeignKey("targets.id"))
    mode: Mapped[str] = mapped_column(String(20), default="passive")
    selected_adapters_json: Mapped[list[str]] = mapped_column(JSON, default=list)
    permission_snapshot_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(20), default="queued")
    started_at: Mapped[datetime] = ts()
    ended_at: Mapped[datetime | None] = ts(nullable=True, default=False)
    summary_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class Finding(Base):
    __tablename__ = "findings"
    id: Mapped[str] = pk()
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"))
    subject_entity_id: Mapped[str] = mapped_column(ForeignKey("entities.id"))
    predicate: Mapped[str] = mapped_column(String(120))
    value_type: Mapped[str] = mapped_column(String(30), default="string")
    value_json: Mapped[Any] = mapped_column(JSON)
    confidence: Mapped[str] = mapped_column(String(12), default="unknown")  # unknown|low|medium|high
    confidence_reason: Mapped[str] = mapped_column(Text, default="")
    evidence_id: Mapped[str] = mapped_column(ForeignKey("evidence.id"))
    source_id: Mapped[str | None] = mapped_column(ForeignKey("sources.id"), nullable=True)
    adapter_id: Mapped[str] = mapped_column(String(80))
    adapter_version: Mapped[str] = mapped_column(String(40), default="")
    observed_at: Mapped[datetime] = ts()
    source_published_at: Mapped[datetime | None] = ts(nullable=True, default=False)
    status: Mapped[str] = mapped_column(String(20), default="unverified")
    run_id: Mapped[str | None] = mapped_column(ForeignKey("search_runs.id"), nullable=True)
    dedup_key: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = ts()
    __table_args__ = (
        Index("ix_findings_case_obs", "case_id", "observed_at"),
        UniqueConstraint("case_id", "dedup_key", name="uq_finding_dedup"),
    )


class Relationship(Base):
    __tablename__ = "relationships"
    id: Mapped[str] = pk()
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"))
    from_entity_id: Mapped[str] = mapped_column(ForeignKey("entities.id"))
    to_entity_id: Mapped[str] = mapped_column(ForeignKey("entities.id"))
    relation_type: Mapped[str] = mapped_column(String(80))
    confidence: Mapped[str] = mapped_column(String(12), default="unknown")
    confidence_reason: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(20), default="unverified")
    asserted_by: Mapped[str] = mapped_column(String(80), default="adapter")
    created_at: Mapped[datetime] = ts()
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, onupdate=utcnow)
    __table_args__ = (
        CheckConstraint("status IN ('unverified','corroborated','rejected','manual')", name="ck_rel_status"),
        UniqueConstraint("case_id", "from_entity_id", "to_entity_id", "relation_type", name="uq_rel"),
        Index("ix_rel_from", "case_id", "from_entity_id"),
        Index("ix_rel_to", "case_id", "to_entity_id"),
    )


class RelationshipEvidence(Base):
    __tablename__ = "relationship_evidence"
    relationship_id: Mapped[str] = mapped_column(
        ForeignKey("relationships.id", ondelete="CASCADE"), primary_key=True)
    evidence_id: Mapped[str] = mapped_column(ForeignKey("evidence.id"), primary_key=True)


class Job(Base):
    __tablename__ = "jobs"
    id: Mapped[str] = pk()
    run_id: Mapped[str] = mapped_column(ForeignKey("search_runs.id", ondelete="CASCADE"), index=True)
    adapter_id: Mapped[str] = mapped_column(String(80))
    status: Mapped[str] = mapped_column(String(20), default="queued")
    idempotency_key: Mapped[str] = mapped_column(String(128), unique=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, default=3)
    next_retry_at: Mapped[datetime | None] = ts(nullable=True, default=False)
    lease_until: Mapped[datetime | None] = ts(nullable=True, default=False)
    last_heartbeat: Mapped[datetime | None] = ts(nullable=True, default=False)
    last_error_code: Mapped[str | None] = mapped_column(String(60), nullable=True)
    result_status: Mapped[str | None] = mapped_column(String(20), nullable=True)
    warnings_json: Mapped[list[str]] = mapped_column(JSON, default=list)
    result_keys_json: Mapped[list[str]] = mapped_column(JSON, default=list)  # finding dedup keys returned by this job
    created_at: Mapped[datetime] = ts()
    started_at: Mapped[datetime | None] = ts(nullable=True, default=False)
    finished_at: Mapped[datetime | None] = ts(nullable=True, default=False)
    __table_args__ = (Index("ix_jobs_status_retry", "status", "next_retry_at"),)


class JobEvent(Base):
    __tablename__ = "job_events"
    id: Mapped[str] = pk()
    job_id: Mapped[str] = mapped_column(ForeignKey("jobs.id", ondelete="CASCADE"), index=True)
    run_id: Mapped[str] = mapped_column(String(36), index=True)
    sequence: Mapped[int] = mapped_column(Integer)
    event_type: Mapped[str] = mapped_column(String(40))
    payload_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    occurred_at: Mapped[datetime] = ts()


class GraphProposal(Base):
    __tablename__ = "graph_proposals"
    id: Mapped[str] = pk()
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"))
    proposal_type: Mapped[str] = mapped_column(String(30), default="merge")
    subject_id: Mapped[str] = mapped_column(ForeignKey("entities.id"))
    candidate_id: Mapped[str] = mapped_column(ForeignKey("entities.id"))
    reason: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(20), default="pending")
    created_at: Mapped[datetime] = ts()
    decided_at: Mapped[datetime | None] = ts(nullable=True, default=False)


class Note(Base):
    __tablename__ = "notes"
    id: Mapped[str] = pk()
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"))
    entity_id: Mapped[str | None] = mapped_column(ForeignKey("entities.id"), nullable=True)
    evidence_id: Mapped[str | None] = mapped_column(ForeignKey("evidence.id"), nullable=True)
    body_markdown: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = ts()
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, onupdate=utcnow)


class ScopeAuthorization(Base):
    __tablename__ = "scope_authorizations"
    id: Mapped[str] = pk()
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"))
    scope_type: Mapped[str] = mapped_column(String(30))
    scope_value: Mapped[str] = mapped_column(Text)
    authorization_type: Mapped[str] = mapped_column(String(40), default="owner")
    authorized_by: Mapped[str] = mapped_column(Text)
    document_ref: Mapped[str | None] = mapped_column(Text, nullable=True)
    allowed_classes_json: Mapped[list[str]] = mapped_column(JSON, default=list)
    expires_at: Mapped[datetime | None] = ts(nullable=True, default=False)
    created_at: Mapped[datetime] = ts()
    revoked_at: Mapped[datetime | None] = ts(nullable=True, default=False)


class AuditEvent(Base):
    __tablename__ = "audit_events"
    id: Mapped[str] = pk()
    seq: Mapped[int] = mapped_column(Integer, unique=True)
    actor_id: Mapped[str] = mapped_column(String(80), default="local")
    case_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    action: Mapped[str] = mapped_column(String(80))
    resource_type: Mapped[str | None] = mapped_column(String(40), nullable=True)
    resource_id: Mapped[str | None] = mapped_column(String(80), nullable=True)
    decision: Mapped[str] = mapped_column(String(20), default="allow")
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    ts: Mapped[datetime] = ts()
    prev_hash: Mapped[str] = mapped_column(String(64))
    event_hash: Mapped[str] = mapped_column(String(64))


class Setting(Base):
    __tablename__ = "settings"
    key: Mapped[str] = mapped_column(String(100), primary_key=True)
    value_json: Mapped[Any] = mapped_column(JSON)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, onupdate=utcnow)


class Requirement(Base):
    __tablename__ = "intelligence_requirements"
    id: Mapped[str] = pk()
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"))
    question: Mapped[str] = mapped_column(Text)
    objective: Mapped[str] = mapped_column(Text, default="")
    information_requirement: Mapped[str] = mapped_column(Text, default="")
    collection_constraint: Mapped[str] = mapped_column(Text, default="")
    assigned_actor: Mapped[str | None] = mapped_column(String(80), nullable=True)
    answer_status: Mapped[str] = mapped_column(String(20), default="unanswered")  # unanswered|partial|answered|unanswerable
    priority: Mapped[str] = mapped_column(String(10), default="medium")
    status: Mapped[str] = mapped_column(String(20), default="open")
    due_at: Mapped[datetime | None] = ts(nullable=True, default=False)
    created_by: Mapped[str] = mapped_column(String(80), default="local")
    answered_at: Mapped[datetime | None] = ts(nullable=True, default=False)


class ReportRun(Base):
    __tablename__ = "report_runs"
    id: Mapped[str] = pk()
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"))
    template: Mapped[str] = mapped_column(String(40))
    export_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    redaction_profile: Mapped[str] = mapped_column(String(30), default="default")
    generated_at: Mapped[datetime] = ts()
    sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    evidence_manifest_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="done")


class Discipline(Base):
    __tablename__ = "disciplines"
    id: Mapped[str] = mapped_column(String(20), primary_key=True)
    label: Mapped[str] = mapped_column(String(80))
    parent_id: Mapped[str | None] = mapped_column(ForeignKey("disciplines.id"), nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)


class Observation(Base):
    """Canonical multi-INT observation envelope (spec 21.3). Facts from a parser; never a verified conclusion."""
    __tablename__ = "observations"
    id: Mapped[str] = pk()
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"))
    discipline_id: Mapped[str] = mapped_column(ForeignKey("disciplines.id"))
    kind: Mapped[str] = mapped_column(String(60))
    access_class: Mapped[str] = mapped_column(String(20), default="IMPORTED")
    observed_at: Mapped[datetime | None] = ts(nullable=True, default=False)
    ingested_at: Mapped[datetime] = ts()
    data_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    raw_evidence_id: Mapped[str] = mapped_column(ForeignKey("evidence.id"))
    derived_from_json: Mapped[list[str]] = mapped_column(JSON, default=list)
    sensitivity: Mapped[str] = mapped_column(String(20), default="INTERNAL")
    confidence: Mapped[str] = mapped_column(String(12), default="unknown")
    review_status: Mapped[str] = mapped_column(String(20), default="UNREVIEWED")
    parser_version: Mapped[str] = mapped_column(String(40), default="")
    __table_args__ = (Index("ix_obs_case_time", "case_id", "observed_at"),
                      Index("ix_obs_disc_kind", "discipline_id", "kind"))


class Role(Base):
    __tablename__ = "roles"
    id: Mapped[str] = pk()
    name: Mapped[str] = mapped_column(String(40), unique=True)


class UserRole(Base):
    __tablename__ = "user_roles"
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), primary_key=True)
    role_id: Mapped[str] = mapped_column(ForeignKey("roles.id"), primary_key=True)


class Claim(Base):
    """A statement about the world supported by evidence. Facts a source reported are claims, never truths."""
    __tablename__ = "claims"
    id: Mapped[str] = pk()
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    subject_entity_id: Mapped[str] = mapped_column(ForeignKey("entities.id"))
    predicate: Mapped[str] = mapped_column(String(120))
    object_entity_id: Mapped[str | None] = mapped_column(ForeignKey("entities.id"), nullable=True)
    value_json: Mapped[Any] = mapped_column(JSON, nullable=True)
    epistemic_status: Mapped[str] = mapped_column(String(20), default="reported")  # observed|reported|inferred
    confidence_label: Mapped[str] = mapped_column(String(12), default="unknown")
    verification_status: Mapped[str] = mapped_column(String(20), default="unverified")  # unverified|analyst_verified|disputed|rejected
    observed_at: Mapped[datetime | None] = ts(nullable=True, default=False)
    created_by: Mapped[str] = mapped_column(String(80), default="local")
    created_at: Mapped[datetime] = ts()
    __table_args__ = (
        CheckConstraint("epistemic_status IN ('observed','reported','inferred')", name="ck_claim_epistemic"),
        CheckConstraint("verification_status IN ('unverified','analyst_verified','disputed','rejected')",
                        name="ck_claim_verification"),
        Index("ix_claim_subject_pred", "case_id", "subject_entity_id", "predicate"),
    )


class ClaimSource(Base):
    __tablename__ = "claim_sources"
    claim_id: Mapped[str] = mapped_column(ForeignKey("claims.id", ondelete="CASCADE"), primary_key=True)
    evidence_id: Mapped[str] = mapped_column(ForeignKey("evidence.id"), primary_key=True)
    method: Mapped[str] = mapped_column(String(60), default="manual")
    independent_source_group: Mapped[str] = mapped_column(String(80), default="")


class Hypothesis(Base):
    __tablename__ = "hypotheses"
    id: Mapped[str] = pk()
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    statement: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(20), default="open")  # open|supported|refuted|unresolved
    rationale: Mapped[str] = mapped_column(Text, default="")
    created_by: Mapped[str] = mapped_column(String(80), default="local")
    created_at: Mapped[datetime] = ts()


class HypothesisClaim(Base):
    __tablename__ = "hypothesis_claims"
    hypothesis_id: Mapped[str] = mapped_column(ForeignKey("hypotheses.id", ondelete="CASCADE"), primary_key=True)
    claim_id: Mapped[str] = mapped_column(ForeignKey("claims.id", ondelete="CASCADE"), primary_key=True)
    stance: Mapped[str] = mapped_column(String(12), default="support")  # support|contradict|neutral


class EntityLink(Base):
    """Reversible analyst merge decision: `entity_id` is treated as `canonical_entity_id` in merged views only."""
    __tablename__ = "entity_links"
    id: Mapped[str] = pk()
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    entity_id: Mapped[str] = mapped_column(ForeignKey("entities.id"))
    canonical_entity_id: Mapped[str] = mapped_column(ForeignKey("entities.id"))
    decided_by: Mapped[str] = mapped_column(String(80))
    reason: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(12), default="active")  # active|reverted
    created_at: Mapped[datetime] = ts()
    reverted_at: Mapped[datetime | None] = ts(nullable=True, default=False)


class RequirementEvidence(Base):
    __tablename__ = "requirement_evidence"
    requirement_id: Mapped[str] = mapped_column(ForeignKey("intelligence_requirements.id", ondelete="CASCADE"),
                                                primary_key=True)
    evidence_id: Mapped[str] = mapped_column(ForeignKey("evidence.id"), primary_key=True)
    claim_id: Mapped[str | None] = mapped_column(ForeignKey("claims.id"), nullable=True)
    relevance_note: Mapped[str] = mapped_column(Text, default="")


class CollectionPlan(Base):
    __tablename__ = "collection_plans"
    id: Mapped[str] = pk()
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    created_by: Mapped[str] = mapped_column(String(80))
    reason: Mapped[str] = mapped_column(Text, default="")
    policy_status: Mapped[str] = mapped_column(String(24), default="allowed")  # allowed|needs_confirmation|denied
    status: Mapped[str] = mapped_column(String(20), default="draft")  # draft|approved|running|completed|cancelled
    run_id: Mapped[str | None] = mapped_column(ForeignKey("search_runs.id"), nullable=True)
    created_at: Mapped[datetime] = ts()
    plan_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class CollectionStep(Base):
    __tablename__ = "collection_steps"
    id: Mapped[str] = pk()
    plan_id: Mapped[str] = mapped_column(ForeignKey("collection_plans.id", ondelete="CASCADE"), index=True)
    adapter_id: Mapped[str] = mapped_column(String(80))
    scope_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(20), default="planned")
    started_at: Mapped[datetime | None] = ts(nullable=True, default=False)
    finished_at: Mapped[datetime | None] = ts(nullable=True, default=False)
    error_code: Mapped[str | None] = mapped_column(String(60), nullable=True)


class GeospatialLayer(Base):
    __tablename__ = "geospatial_layers"
    id: Mapped[str] = pk()
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    file_evidence_id: Mapped[str] = mapped_column(ForeignKey("evidence.id"))
    coordinate_system: Mapped[str | None] = mapped_column(String(40), nullable=True)
    bounds_json: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    acquisition_time: Mapped[datetime | None] = ts(nullable=True, default=False)
    imagery_licence: Mapped[str | None] = mapped_column(Text, nullable=True)
    precision_class: Mapped[str] = mapped_column(String(20), default="UNKNOWN")  # UNKNOWN|COARSE|FINE
    pixel_size: Mapped[float | None] = mapped_column(nullable=True)
    width: Mapped[int | None] = mapped_column(Integer, nullable=True)
    height: Mapped[int | None] = mapped_column(Integer, nullable=True)


class ConsentAuthorization(Base):
    __tablename__ = "consent_authorizations"
    id: Mapped[str] = pk()
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    basis: Mapped[str] = mapped_column(String(40))  # informed_consent | contract | public_interview | legal_duty
    authorizing_party: Mapped[str] = mapped_column(String(200))  # who gave consent, by alias or role (not required to be a name)
    scope_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    expires_at: Mapped[datetime | None] = ts(nullable=True, default=False)
    revoked_at: Mapped[datetime | None] = ts(nullable=True, default=False)
    supporting_evidence_id: Mapped[str | None] = mapped_column(ForeignKey("evidence.id"), nullable=True)
    created_at: Mapped[datetime] = ts()


class HumanSource(Base):
    """A source known to the case ONLY by alias. Reliability/credibility are analyst judgements, never computed."""
    __tablename__ = "human_sources"
    id: Mapped[str] = pk()
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    alias: Mapped[str] = mapped_column(String(80))
    consent_id: Mapped[str] = mapped_column(ForeignKey("consent_authorizations.id"))
    reliability_assessment: Mapped[str | None] = mapped_column(String(1), nullable=True)  # A-F (NATO/Admiralty) or None
    retention_until: Mapped[datetime | None] = ts(nullable=True, default=False)
    restricted: Mapped[bool] = mapped_column(Boolean, default=True)
    revoked_at: Mapped[datetime | None] = ts(nullable=True, default=False)
    created_at: Mapped[datetime] = ts()
    __table_args__ = (UniqueConstraint("case_id", "alias", name="uq_human_alias"),)


class Workflow(Base):
    __tablename__ = "workflows"
    id: Mapped[str] = pk()
    case_id: Mapped[str | None] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), nullable=True, index=True)
    name: Mapped[str] = mapped_column(String(200))
    definition_json: Mapped[dict[str, Any]] = mapped_column(JSON)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_by: Mapped[str] = mapped_column(String(80), default="local")
    created_at: Mapped[datetime] = ts()
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, onupdate=utcnow)


class WorkflowRun(Base):
    __tablename__ = "workflow_runs"
    id: Mapped[str] = pk()
    workflow_id: Mapped[str] = mapped_column(ForeignKey("workflows.id", ondelete="CASCADE"), index=True)
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"))
    target_id: Mapped[str] = mapped_column(ForeignKey("targets.id"))
    trigger: Mapped[str] = mapped_column(String(20), default="manual")  # manual | schedule
    slot_key: Mapped[str | None] = mapped_column(String(120), nullable=True, unique=True)  # idempotency for scheduled slots
    status: Mapped[str] = mapped_column(String(20), default="running")
    started_at: Mapped[datetime] = ts()
    ended_at: Mapped[datetime | None] = ts(nullable=True, default=False)
    run_ids_json: Mapped[list[str]] = mapped_column(JSON, default=list)
    summary_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class Schedule(Base):
    __tablename__ = "schedules"
    id: Mapped[str] = pk()
    workflow_id: Mapped[str] = mapped_column(ForeignKey("workflows.id", ondelete="CASCADE"), index=True)
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"))
    target_raw: Mapped[str] = mapped_column(Text)
    target_type: Mapped[str | None] = mapped_column(String(20), nullable=True)
    cron_or_interval: Mapped[str] = mapped_column(String(20))  # e.g. 15m, 6h, 1d
    next_run_at: Mapped[datetime] = ts()
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)  # monitoring is OFF until explicitly enabled
    last_run_at: Mapped[datetime | None] = ts(nullable=True, default=False)
    last_status: Mapped[str | None] = mapped_column(String(40), nullable=True)
    consecutive_failures: Mapped[int] = mapped_column(Integer, default=0)
    confirmed_adapters_json: Mapped[list[str]] = mapped_column(JSON, default=list)
    target_policy_snapshot_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_by: Mapped[str] = mapped_column(String(80), default="local")
    created_at: Mapped[datetime] = ts()


class Snapshot(Base):
    __tablename__ = "snapshots"
    id: Mapped[str] = pk()
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    workflow_id: Mapped[str] = mapped_column(ForeignKey("workflows.id", ondelete="CASCADE"))
    target_id: Mapped[str] = mapped_column(ForeignKey("targets.id"))
    fingerprint: Mapped[str] = mapped_column(String(64))
    keys_json: Mapped[list[str]] = mapped_column(JSON, default=list)
    workflow_run_id: Mapped[str | None] = mapped_column(ForeignKey("workflow_runs.id"), nullable=True)
    created_at: Mapped[datetime] = ts()


class Alert(Base):
    __tablename__ = "alerts"
    id: Mapped[str] = pk()
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    type: Mapped[str] = mapped_column(String(40))
    severity: Mapped[str] = mapped_column(String(10), default="info")
    subject_entity_id: Mapped[str | None] = mapped_column(ForeignKey("entities.id"), nullable=True)
    old_fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True)
    new_fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True)
    message: Mapped[str] = mapped_column(Text)
    details_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    acknowledged_at: Mapped[datetime | None] = ts(nullable=True, default=False)
    created_at: Mapped[datetime] = ts()


class AiProfile(Base):
    __tablename__ = "ai_profiles"
    id: Mapped[str] = pk()
    name: Mapped[str] = mapped_column(String(80), unique=True)
    provider_type: Mapped[str] = mapped_column(String(20))  # ollama | llamacpp | openai_compat | fixture
    model_id: Mapped[str] = mapped_column(String(200))  # any string: no curated allowlist
    local_only: Mapped[bool] = mapped_column(Boolean, default=True)
    config_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)  # base_url, secret_name (never the secret)
    created_at: Mapped[datetime] = ts()


class CaseAiPolicy(Base):
    __tablename__ = "case_ai_policies"
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), primary_key=True)
    allow_cloud: Mapped[bool] = mapped_column(Boolean, default=False)
    require_preview: Mapped[bool] = mapped_column(Boolean, default=True)
    deny_sensitive_cloud: Mapped[bool] = mapped_column(Boolean, default=True)


class AiCall(Base):
    __tablename__ = "ai_calls"
    id: Mapped[str] = pk()
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    actor_id: Mapped[str] = mapped_column(String(80))
    provider_type: Mapped[str] = mapped_column(String(20))
    model_id: Mapped[str] = mapped_column(String(200))
    evidence_refs_json: Mapped[list[str]] = mapped_column(JSON, default=list)
    cloud_transfer_approved: Mapped[bool] = mapped_column(Boolean, default=False)
    payload_sha256: Mapped[str] = mapped_column(String(64), default="")
    outcome: Mapped[str] = mapped_column(String(30), default="ok")
    created_at: Mapped[datetime] = ts()


class McpApproval(Base):
    """A state-changing MCP request waits here until the person approves it in the app (not through MCP)."""
    __tablename__ = "mcp_approvals"
    id: Mapped[str] = pk()
    tool: Mapped[str] = mapped_column(String(40))
    args_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    case_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    client: Mapped[str] = mapped_column(String(120), default="unknown")
    status: Mapped[str] = mapped_column(String(12), default="pending")  # pending|approved|denied|used
    created_at: Mapped[datetime] = ts()
    decided_at: Mapped[datetime | None] = ts(nullable=True, default=False)
    used_at: Mapped[datetime | None] = ts(nullable=True, default=False)


class HardwareDevice(Base):
    __tablename__ = "hardware_devices"
    id: Mapped[str] = pk()
    driver_id: Mapped[str] = mapped_column(String(40))
    device_kind: Mapped[str] = mapped_column(String(20))  # sdr | environmental | gps | replay
    logical_name: Mapped[str] = mapped_column(String(120))
    hw_key: Mapped[str] = mapped_column(String(160))  # driver-provided stable identity (hashed serial)
    permission_scope: Mapped[str] = mapped_column(String(30), default="read_only")
    receive_only: Mapped[bool] = mapped_column(Boolean, default=True)
    simulated: Mapped[bool] = mapped_column(Boolean, default=False)
    present: Mapped[bool] = mapped_column(Boolean, default=True)
    last_seen_at: Mapped[datetime] = ts()
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    __table_args__ = (UniqueConstraint("driver_id", "hw_key", name="uq_hw"),)


class CaptureSession(Base):
    __tablename__ = "capture_sessions"
    id: Mapped[str] = pk()
    device_id: Mapped[str] = mapped_column(ForeignKey("hardware_devices.id"))
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    status: Mapped[str] = mapped_column(String(20), default="recording")  # recording|stopped|completed|interrupted|failed
    capture_scope_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    started_at: Mapped[datetime] = ts()
    ended_at: Mapped[datetime | None] = ts(nullable=True, default=False)
    artifact_id: Mapped[str | None] = mapped_column(ForeignKey("evidence.id"), nullable=True)
    started_by: Mapped[str] = mapped_column(String(80), default="local")
    clock_sync: Mapped[str] = mapped_column(String(30), default="unverified")
    detail: Mapped[str] = mapped_column(Text, default="")


class PluginManifest(Base):
    __tablename__ = "plugin_manifests"
    id: Mapped[str] = pk()
    plugin_id: Mapped[str] = mapped_column(String(60), index=True)
    version: Mapped[str] = mapped_column(String(30))
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)  # OFF until a person reviews and enables it
    is_active: Mapped[bool] = mapped_column(Boolean, default=False)
    license: Mapped[str] = mapped_column(String(80), default="")
    entry_sha256: Mapped[str] = mapped_column(String(64))
    capabilities_json: Mapped[list[str]] = mapped_column(JSON, default=list)
    permission_manifest_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    manifest_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    health_status: Mapped[str] = mapped_column(String(20), default="unknown")
    invalid_outputs: Mapped[int] = mapped_column(Integer, default=0)
    reviewed_by: Mapped[str | None] = mapped_column(String(80), nullable=True)
    reviewed_at: Mapped[datetime | None] = ts(nullable=True, default=False)
    installed_at: Mapped[datetime] = ts()
    __table_args__ = (UniqueConstraint("plugin_id", "version", name="uq_plugin_version"),)


class Correlation(Base):
    """An analyst decision about a suggested coincidence between two observations. Coincidence is not a relationship."""
    __tablename__ = "correlations"
    id: Mapped[str] = pk()
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    obs_a_id: Mapped[str] = mapped_column(ForeignKey("observations.id", ondelete="CASCADE"))
    obs_b_id: Mapped[str] = mapped_column(ForeignKey("observations.id", ondelete="CASCADE"))
    kind: Mapped[str] = mapped_column(String(12))  # temporal | spatial | both
    status: Mapped[str] = mapped_column(String(12), default="accepted")  # accepted | rejected | revoked
    note: Mapped[str] = mapped_column(Text, default="")
    delta_s: Mapped[float | None] = mapped_column(nullable=True)
    distance_m: Mapped[float | None] = mapped_column(nullable=True)
    decided_by: Mapped[str] = mapped_column(String(80), default="local")
    decided_at: Mapped[datetime] = ts()
    __table_args__ = (UniqueConstraint("case_id", "obs_a_id", "obs_b_id", "kind", name="uq_correlation"),)


class CopilotConversation(Base):
    """A Copilot chat. One per investigation per user (plus general ones); history survives restarts."""
    __tablename__ = "copilot_conversations"
    id: Mapped[str] = pk()
    user_id: Mapped[str] = mapped_column(String(80), index=True)
    case_id: Mapped[str | None] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), nullable=True, index=True)
    title: Mapped[str] = mapped_column(String(200), default="New conversation")
    mode: Mapped[str] = mapped_column(String(20), default="general")  # general | investigation | tutor (the last one used)
    created_at: Mapped[datetime] = ts()
    updated_at: Mapped[datetime] = ts()


class CopilotMessage(Base):
    __tablename__ = "copilot_messages"
    id: Mapped[str] = pk()
    conversation_id: Mapped[str] = mapped_column(ForeignKey("copilot_conversations.id", ondelete="CASCADE"), index=True)
    seq: Mapped[int] = mapped_column(Integer)
    role: Mapped[str] = mapped_column(String(12))  # user | assistant | note
    mode: Mapped[str] = mapped_column(String(20), default="general")
    content: Mapped[str] = mapped_column(Text, default="")
    meta_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)  # sources, tool results, proposals, model, page context
    created_at: Mapped[datetime] = ts()
    __table_args__ = (Index("ix_copilot_msg_conv_seq", "conversation_id", "seq"),)


class CopilotProposal(Base):
    """An action the Copilot suggested. Nothing runs until a person approves exactly this proposal."""
    __tablename__ = "copilot_proposals"
    id: Mapped[str] = pk()
    conversation_id: Mapped[str] = mapped_column(ForeignKey("copilot_conversations.id", ondelete="CASCADE"), index=True)
    case_id: Mapped[str | None] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), nullable=True)
    tool: Mapped[str] = mapped_column(String(40))
    args_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    preview_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(12), default="pending")  # pending | approved | rejected | executed | failed
    result_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = ts()
    decided_at: Mapped[datetime | None] = ts(nullable=True, default=False)
    decided_by: Mapped[str | None] = mapped_column(String(80), nullable=True)


# ---- AI Automation Builder & Workflow Library (addendum A1.0) -------------------------------------------------------------------------------
class AutomationWorkflow(Base):
    """An editable draft plus a pointer to the active immutable version. owner_id/team_id leave room for multiuser sharing."""
    __tablename__ = "automation_workflows"
    id: Mapped[str] = pk()
    case_id: Mapped[str | None] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), nullable=True, index=True)
    owner_id: Mapped[str] = mapped_column(String(80), index=True)
    team_id: Mapped[str | None] = mapped_column(String(80), nullable=True)
    name: Mapped[str] = mapped_column(String(200))
    template_slug: Mapped[str | None] = mapped_column(String(40), nullable=True)
    draft_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    draft_rev: Mapped[int] = mapped_column(Integer, default=1)          # optimistic concurrency (ETag)
    active_version_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    state: Mapped[str] = mapped_column(String(16), default="draft")     # draft | published | active | disabled
    created_at: Mapped[datetime] = ts()
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, onupdate=utcnow)
    deleted_at: Mapped[datetime | None] = ts(nullable=True, default=False)


class AutomationVersion(Base):
    __tablename__ = "automation_versions"
    id: Mapped[str] = pk()
    workflow_id: Mapped[str] = mapped_column(ForeignKey("automation_workflows.id", ondelete="CASCADE"), index=True)
    revision: Mapped[int] = mapped_column(Integer)
    definition_json: Mapped[dict[str, Any]] = mapped_column(JSON)
    schema_version: Mapped[int] = mapped_column(Integer, default=1)
    content_hash: Mapped[str] = mapped_column(String(64))
    created_by: Mapped[str] = mapped_column(String(80))
    created_at: Mapped[datetime] = ts()
    published_at: Mapped[datetime | None] = ts(nullable=True, default=False)
    __table_args__ = (UniqueConstraint("workflow_id", "revision", name="uq_automation_version"),)


class AutomationTrigger(Base):
    __tablename__ = "automation_triggers"
    id: Mapped[str] = pk()
    workflow_id: Mapped[str] = mapped_column(ForeignKey("automation_workflows.id", ondelete="CASCADE"))
    version_id: Mapped[str] = mapped_column(ForeignKey("automation_versions.id", ondelete="CASCADE"))
    type: Mapped[str] = mapped_column(String(16))                        # manual | schedule | event | file
    schedule: Mapped[str | None] = mapped_column(String(80), nullable=True)   # 5-field cron
    timezone: Mapped[str] = mapped_column(String(64), default="UTC")           # IANA zone; instants are stored in UTC
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    missed_run_policy: Mapped[str] = mapped_column(String(12), default="coalesce")  # skip | coalesce | catch_up
    next_due_at: Mapped[datetime | None] = ts(nullable=True, default=False)
    last_fired_at: Mapped[datetime | None] = ts(nullable=True, default=False)
    config_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    __table_args__ = (Index("ix_automation_trigger_due", "enabled", "next_due_at"),)


class AutomationApproval(Base):
    __tablename__ = "automation_approvals"
    id: Mapped[str] = pk()
    workflow_id: Mapped[str] = mapped_column(ForeignKey("automation_workflows.id", ondelete="CASCADE"), index=True)
    version_id: Mapped[str] = mapped_column(ForeignKey("automation_versions.id", ondelete="CASCADE"))
    kind: Mapped[str] = mapped_column(String(12))                         # activation | collection
    authorization_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    approver_id: Mapped[str | None] = mapped_column(String(80), nullable=True)
    action_scope_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(12), default="pending")    # pending | approved | rejected | revoked
    requested_at: Mapped[datetime] = ts()
    approved_at: Mapped[datetime | None] = ts(nullable=True, default=False)
    expires_at: Mapped[datetime | None] = ts(nullable=True, default=False)
    revoked_at: Mapped[datetime | None] = ts(nullable=True, default=False)


class AutomationRun(Base):
    __tablename__ = "automation_runs"
    id: Mapped[str] = pk()
    workflow_id: Mapped[str] = mapped_column(ForeignKey("automation_workflows.id", ondelete="CASCADE"))
    version_id: Mapped[str | None] = mapped_column(String(36), nullable=True)       # null for dry runs of an unpublished draft
    case_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    trigger_type: Mapped[str] = mapped_column(String(16), default="manual")
    trigger_event_id: Mapped[str | None] = mapped_column(String(80), nullable=True)
    state: Mapped[str] = mapped_column(String(24), default="queued")
    dry_run: Mapped[bool] = mapped_column(Boolean, default=False)
    queued_at: Mapped[datetime] = ts()
    started_at: Mapped[datetime | None] = ts(nullable=True, default=False)
    ended_at: Mapped[datetime | None] = ts(nullable=True, default=False)
    idempotency_key: Mapped[str] = mapped_column(String(160), unique=True)
    error_code: Mapped[str | None] = mapped_column(String(40), nullable=True)
    evidence_count: Mapped[int] = mapped_column(Integer, default=0)
    inputs_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    summary_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    cancel_requested: Mapped[bool] = mapped_column(Boolean, default=False)
    lease_until: Mapped[datetime | None] = ts(nullable=True, default=False)
    created_by: Mapped[str] = mapped_column(String(80), default="local")
    __table_args__ = (Index("ix_automation_run_wf", "workflow_id", "queued_at"), Index("ix_automation_run_state", "state", "queued_at"))


class AutomationNodeRun(Base):
    __tablename__ = "automation_node_runs"
    id: Mapped[str] = pk()
    run_id: Mapped[str] = mapped_column(ForeignKey("automation_runs.id", ondelete="CASCADE"))
    node_id: Mapped[str] = mapped_column(String(40))
    attempt: Mapped[int] = mapped_column(Integer, default=1)
    state: Mapped[str] = mapped_column(String(16), default="running")     # running | succeeded | failed | skipped | interrupted | waiting
    started_at: Mapped[datetime] = ts()
    ended_at: Mapped[datetime | None] = ts(nullable=True, default=False)
    input_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    output_json: Mapped[Any] = mapped_column(JSON, nullable=True)
    error_code: Mapped[str | None] = mapped_column(String(40), nullable=True)
    diagnostics_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    __table_args__ = (Index("ix_automation_node_run", "run_id", "node_id"),)


class AutomationSnapshot(Base):
    __tablename__ = "automation_snapshots"
    id: Mapped[str] = pk()
    workflow_id: Mapped[str] = mapped_column(ForeignKey("automation_workflows.id", ondelete="CASCADE"))
    case_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    node_id: Mapped[str] = mapped_column(String(40), default="")
    dataset_type: Mapped[str] = mapped_column(String(30), default="findings")
    content_hash: Mapped[str] = mapped_column(String(64))
    items_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)      # stable id -> value digest (+ short description)
    taken_at: Mapped[datetime] = ts()
    source_run_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    __table_args__ = (Index("ix_automation_snapshot_wf", "workflow_id", "taken_at"),)


class AutomationNotification(Base):
    __tablename__ = "automation_notifications"
    id: Mapped[str] = pk()
    run_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    workflow_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    owner_id: Mapped[str] = mapped_column(String(80), default="local", index=True)
    channel: Mapped[str] = mapped_column(String(20))                       # in_app | local_desktop | webhook
    destination_ref: Mapped[str | None] = mapped_column(String(200), nullable=True)
    dedupe_key: Mapped[str] = mapped_column(String(80), index=True)
    severity: Mapped[str] = mapped_column(String(10), default="info")
    status: Mapped[str] = mapped_column(String(16), default="delivered")   # delivered | held | digest_pending | suppressed | failed
    title: Mapped[str] = mapped_column(String(200), default="")
    body: Mapped[str] = mapped_column(Text, default="")
    details_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    count: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = ts()
    delivered_at: Mapped[datetime | None] = ts(nullable=True, default=False)
    acknowledged_at: Mapped[datetime | None] = ts(nullable=True, default=False)


class AutomationSuggestion(Base):
    __tablename__ = "automation_suggestions"
    id: Mapped[str] = pk()
    owner_id: Mapped[str] = mapped_column(String(80), index=True)
    case_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    rationale: Mapped[str] = mapped_column(Text)
    basis_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    proposed_template_key: Mapped[str] = mapped_column(String(40))
    category: Mapped[str] = mapped_column(String(20), default="repeat_search")
    state: Mapped[str] = mapped_column(String(12), default="open")         # open | dismissed | snoozed | accepted
    snooze_until: Mapped[datetime | None] = ts(nullable=True, default=False)
    created_at: Mapped[datetime] = ts()
    dismissed_at: Mapped[datetime | None] = ts(nullable=True, default=False)


from .aiv import (  # noqa: F401  (Active Intelligence & Verification tables, addendum v1.1)
    AivApproval,
    AivObservation,
    AivPlan,
    AivRun,
    AivRunEvent,
    AivTemplateApproval,
    AssetAuthorization,
)
from .darkint import (  # noqa: F401
    ExposureCheck,
    ExposureEvent,
    ExposureMonitorConfig,
    ExposureReview,
    ExposureSource,
)
from .profile import (  # noqa: F401  (target-profile tables, addendum TP-1.0)
    AssociatedEmail,
    ExpansionRun,
    ExposureIndicator,
    ImageAsset,
    ImageMatch,
    ProfileCandidateLink,
    ProfileClaim,
    ProfileReviewEvent,
    RemediationTask,
    ResearchTask,
    RetentionAction,
    Subject,
    SubjectConsent,
    SubjectCorrection,
    SubjectIdentifier,
)
