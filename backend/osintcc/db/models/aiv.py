"""Active Intelligence & Verification tables (addendum v1.1 section 7). Case-scoped, in the same encrypted database.

`asset_authorizations` is deliberately separate from the legacy `scope_authorizations`: it carries asset-owner proof, ports, paths, budgets and windows.
Nothing here can hold a credential, a payload or a command.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from ..base import Base
from . import pk, ts


class AssetAuthorization(Base):
    __tablename__ = "asset_authorizations"
    id: Mapped[str] = pk()
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    owner_subject_id: Mapped[str | None] = mapped_column(ForeignKey("subjects.id", ondelete="SET NULL"), nullable=True)
    asset_type: Mapped[str] = mapped_column(String(12))                       # fqdn | ip | cidr | url_prefix
    canonical_scope: Mapped[list[str]] = mapped_column(JSON, default=list)    # exact FQDNs, IPs, CIDRs or URL prefixes (a '*.' wildcard covers ONE label)
    ports_json: Mapped[list[int]] = mapped_column(JSON, default=list)
    paths_json: Mapped[list[str]] = mapped_column(JSON, default=list)
    allowed_classes_json: Mapped[list[str]] = mapped_column(JSON, default=list)
    exclusions_json: Mapped[list[str]] = mapped_column(JSON, default=list)
    limits_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)   # budgets, windows, timezone
    authorized_by: Mapped[str] = mapped_column(String(200))
    authority_role: Mapped[str] = mapped_column(String(120), default="")
    source_of_authority: Mapped[str] = mapped_column(Text, default="")
    attestation_kind: Mapped[str] = mapped_column(String(32), default="owner_statement")
    attestation_ref: Mapped[str | None] = mapped_column(ForeignKey("evidence.id"), nullable=True)
    domain_verifications: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)   # provider -> operator attestation of provider-side domain verification
    starts_at: Mapped[datetime] = ts()
    expires_at: Mapped[datetime] = ts()
    revoked_at: Mapped[datetime | None] = ts(nullable=True, default=False)
    retention_terms: Mapped[str] = mapped_column(Text, default="")
    notes: Mapped[str] = mapped_column(Text, default="")
    created_by: Mapped[str] = mapped_column(String(80), default="local")
    created_at: Mapped[datetime] = ts()


class AivPlan(Base):
    __tablename__ = "aiv_plans"
    id: Mapped[str] = pk()
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    target_profile_id: Mapped[str | None] = mapped_column(ForeignKey("subjects.id", ondelete="SET NULL"), nullable=True)
    asset_authorization_id: Mapped[str] = mapped_column(ForeignKey("asset_authorizations.id"))
    plan_hash: Mapped[str] = mapped_column(String(64))
    version: Mapped[int] = mapped_column(Integer, default=1)
    supersedes_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    steps_json: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    projected_limits_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(16), default="draft")
    created_by: Mapped[str] = mapped_column(String(80), default="local")
    created_at: Mapped[datetime] = ts()
    __table_args__ = (UniqueConstraint("case_id", "plan_hash", "version", name="uq_aiv_plan_version"),)


class AivApproval(Base):
    __tablename__ = "aiv_approvals"
    id: Mapped[str] = pk()
    plan_id: Mapped[str] = mapped_column(ForeignKey("aiv_plans.id", ondelete="CASCADE"), index=True)
    plan_version: Mapped[int] = mapped_column(Integer)
    plan_hash: Mapped[str] = mapped_column(String(64))
    approver_id: Mapped[str] = mapped_column(String(80))
    approved_at: Mapped[datetime] = ts()
    expires_at: Mapped[datetime] = ts()
    maximum_uses: Mapped[int] = mapped_column(Integer, default=1)
    uses: Mapped[int] = mapped_column(Integer, default=0)
    revoked_at: Mapped[datetime | None] = ts(nullable=True, default=False)


class AivRun(Base):
    __tablename__ = "aiv_runs"
    id: Mapped[str] = pk()
    plan_id: Mapped[str] = mapped_column(ForeignKey("aiv_plans.id", ondelete="CASCADE"), index=True)
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    approval_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    actor_id: Mapped[str] = mapped_column(String(80))
    status: Mapped[str] = mapped_column(String(16), default="queued")      # queued | running | completed | partial | failed | cancelled | interrupted | refused
    started_at: Mapped[datetime] = ts()
    finished_at: Mapped[datetime | None] = ts(nullable=True, default=False)
    actual_request_counts_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    tool_versions_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    abort_reason: Mapped[str] = mapped_column(Text, default="")
    scope_snapshot_hash: Mapped[str] = mapped_column(String(64), default="")


class AivRunEvent(Base):
    __tablename__ = "aiv_run_events"
    id: Mapped[str] = pk()
    run_id: Mapped[str] = mapped_column(ForeignKey("aiv_runs.id", ondelete="CASCADE"), index=True)
    seq: Mapped[int] = mapped_column(Integer)
    kind: Mapped[str] = mapped_column(String(32))
    payload_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    at: Mapped[datetime] = ts()
    __table_args__ = (Index("ix_aiv_event_run_seq", "run_id", "seq"),)


class AivObservation(Base):
    __tablename__ = "aiv_observations"
    id: Mapped[str] = pk()
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("aiv_runs.id", ondelete="CASCADE"), index=True)
    asset_authorization_id: Mapped[str] = mapped_column(ForeignKey("asset_authorizations.id"))
    target_asset: Mapped[str] = mapped_column(String(300))
    check_type: Mapped[str] = mapped_column(String(40))
    finding_key: Mapped[str] = mapped_column(String(64), default="")        # stable across runs, for reverification comparison
    observed_value_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    severity: Mapped[str] = mapped_column(String(12), default="info")      # info | low | medium | high
    confidence: Mapped[str] = mapped_column(String(12), default="medium")
    basis: Mapped[str] = mapped_column(String(12), default="observed")      # observed | inferred
    remediation: Mapped[str] = mapped_column(Text, default="")
    evidence_id: Mapped[str | None] = mapped_column(ForeignKey("evidence.id"), nullable=True)
    observed_at: Mapped[datetime] = ts()
    review_status: Mapped[str] = mapped_column(String(16), default="unreviewed")   # unreviewed | confirmed | false_positive | accepted_risk
    reviewer: Mapped[str | None] = mapped_column(String(80), nullable=True)
    review_note: Mapped[str] = mapped_column(Text, default="")
    reviewed_at: Mapped[datetime | None] = ts(nullable=True, default=False)
    __table_args__ = (Index("ix_aiv_obs_asset_key", "asset_authorization_id", "finding_key"),)


class AivTemplateApproval(Base):
    """A reviewed signature template, pinned by id AND content hash. Anything else is refused."""
    __tablename__ = "aiv_template_approvals"
    id: Mapped[str] = pk()
    template_id: Mapped[str] = mapped_column(String(120), index=True)
    sha256: Mapped[str] = mapped_column(String(64))
    content: Mapped[str] = mapped_column(Text)
    semantics_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    reviewed_by: Mapped[str] = mapped_column(String(80))
    reviewed_at: Mapped[datetime] = ts()
    revoked_at: Mapped[datetime | None] = ts(nullable=True, default=False)
    notes: Mapped[str] = mapped_column(Text, default="")
    __table_args__ = (UniqueConstraint("template_id", "sha256", name="uq_aiv_template_hash"),)
