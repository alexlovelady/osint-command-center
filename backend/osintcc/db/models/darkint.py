"""DARKINT tables (addendum v1.1 section 14.5). Case-scoped, same encrypted database.

Deliberately absent: any column that could hold a plaintext password, a password hash, a token, a card or government number, or a leaked record. Events carry
a masked title, data CATEGORIES, provider references and timestamps only. Identifiers are referenced by id and a keyed token, never copied.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Boolean, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from ..base import Base
from . import pk, ts


class ExposureSource(Base):
    """Operator state per provider. Static facts (licence, terms, coverage limits) live in code; this row holds only what the operator decided and what was last observed."""
    __tablename__ = "exposure_sources"
    id: Mapped[str] = pk()
    provider_id: Mapped[str] = mapped_column(String(40), unique=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    last_verification_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    terms_acknowledged_at: Mapped[datetime | None] = ts(nullable=True, default=False)
    terms_acknowledged_by: Mapped[str | None] = mapped_column(String(80), nullable=True)
    updated_at: Mapped[datetime] = ts()


class ExposureEvent(Base):
    __tablename__ = "exposure_events"
    id: Mapped[str] = pk()
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    subject_id: Mapped[str | None] = mapped_column(ForeignKey("subjects.id", ondelete="CASCADE"), nullable=True, index=True)
    indicator_id: Mapped[str | None] = mapped_column(ForeignKey("exposure_indicators.id", ondelete="SET NULL"), nullable=True)
    identifier_id: Mapped[str | None] = mapped_column(ForeignKey("subject_identifiers.id", ondelete="SET NULL"), nullable=True)
    identifier_token: Mapped[str] = mapped_column(String(32), default="")           # keyed hash; lets events be grouped without copying the identifier
    provider_id: Mapped[str] = mapped_column(String(40))
    event_type: Mapped[str] = mapped_column(String(24))                              # breach | paste | darkweb_mention | ransomware_listing | advisory | manual_report | mention
    incident_key: Mapped[str] = mapped_column(String(160), default="")
    group_key: Mapped[str] = mapped_column(String(80), default="", index=True)
    title: Mapped[str] = mapped_column(String(200), default="")
    categories_json: Mapped[list[str]] = mapped_column(JSON, default=list)
    reported_first_seen: Mapped[datetime | None] = ts(nullable=True, default=False)
    reported_last_seen: Mapped[datetime | None] = ts(nullable=True, default=False)
    claim_status: Mapped[str] = mapped_column(String(16), default="reported")        # reported | corroborated | disputed | retracted
    confidence: Mapped[str] = mapped_column(String(10), default="low")
    evidence_id: Mapped[str | None] = mapped_column(ForeignKey("evidence.id"), nullable=True)
    provider_ref: Mapped[str] = mapped_column(String(300), default="")
    redacted: Mapped[bool] = mapped_column(Boolean, default=False)
    dedupe_key: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = ts()
    __table_args__ = (UniqueConstraint("case_id", "dedupe_key", name="uq_exposure_event_dedupe"), Index("ix_exposure_event_subject_group", "subject_id", "group_key"))


class ExposureReview(Base):
    __tablename__ = "exposure_reviews"
    id: Mapped[str] = pk()
    event_id: Mapped[str] = mapped_column(ForeignKey("exposure_events.id", ondelete="CASCADE"), index=True)
    reviewer: Mapped[str] = mapped_column(String(80))
    status: Mapped[str] = mapped_column(String(20))        # acknowledged | relevant | not_relevant | corroborated | resolved | accepted_risk
    rationale: Mapped[str] = mapped_column(Text, default="")
    action_items_json: Mapped[list[str]] = mapped_column(JSON, default=list)
    review_source: Mapped[str] = mapped_column(String(40), default="manual")
    created_at: Mapped[datetime] = ts()


class ExposureMonitorConfig(Base):
    """A bounded, expiring scope that a scheduled workflow may use. It holds references to identifiers and an authorization, never values."""
    __tablename__ = "exposure_monitor_configs"
    id: Mapped[str] = pk()
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    subject_id: Mapped[str] = mapped_column(ForeignKey("subjects.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(120))
    identifier_ids_json: Mapped[list[str]] = mapped_column(JSON, default=list)
    providers_json: Mapped[list[str]] = mapped_column(JSON, default=list)
    cadence_hours: Mapped[int] = mapped_column(Integer, default=168)
    consent_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    expires_at: Mapped[datetime] = ts()
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    disabled_reason: Mapped[str] = mapped_column(String(200), default="")
    last_run_at: Mapped[datetime | None] = ts(nullable=True, default=False)
    last_outcome_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_by: Mapped[str] = mapped_column(String(80), default="local")
    created_at: Mapped[datetime] = ts()


class ExposureCheck(Base):
    """One attempt to ask one provider about one identifier, and how it ended. This is what makes 'not checked', 'unknown' and 'no match' distinguishable."""
    __tablename__ = "exposure_checks"
    id: Mapped[str] = pk()
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    subject_id: Mapped[str] = mapped_column(ForeignKey("subjects.id", ondelete="CASCADE"), index=True)
    identifier_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    provider_id: Mapped[str] = mapped_column(String(40))
    operation: Mapped[str] = mapped_column(String(32))
    outcome: Mapped[str] = mapped_column(String(24))   # match | no_match | credential_missing | source_unavailable | rate_limited | unsupported | blocked | offline | error
    events_found: Mapped[int] = mapped_column(Integer, default=0)
    evidence_id: Mapped[str | None] = mapped_column(ForeignKey("evidence.id"), nullable=True)
    detail: Mapped[str] = mapped_column(String(300), default="")
    actor: Mapped[str] = mapped_column(String(80), default="local")
    checked_at: Mapped[datetime] = ts()
