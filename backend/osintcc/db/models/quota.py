"""Provider quota tables (addendum PQ-1.0). Stored in the same encrypted database as everything else.

Deliberately absent: any column that could hold an API key, token, PIN or a target identifier. `account_key` is a short one-way fingerprint of the
credential (never the credential), and `url_host` is a host name only.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Boolean, Float, Index, Integer, PrimaryKeyConstraint, String
from sqlalchemy.orm import Mapped, mapped_column

from ..base import Base
from . import pk, ts


class ProviderLedger(Base):
    """One row per outbound provider request that was reserved. Rolling and calendar windows are computed from these rows, so counters survive a restart."""
    __tablename__ = "provider_ledger"
    id: Mapped[str] = pk()
    provider: Mapped[str] = mapped_column(String(40))
    operation: Mapped[str] = mapped_column(String(40))
    account_key: Mapped[str] = mapped_column(String(24), default="anon")
    case_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    job_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    url_host: Mapped[str] = mapped_column(String(120), default="")
    state: Mapped[str] = mapped_column(String(12), default="inflight")   # inflight | settled | released | expired
    cost: Mapped[float] = mapped_column(Float, default=1.0)               # credits / units charged to the credits window
    reserved_at: Mapped[datetime] = ts()
    finished_at: Mapped[datetime | None] = ts(nullable=True, default=False)
    lease_until: Mapped[datetime | None] = ts(nullable=True, default=False)
    http_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    classification: Mapped[str] = mapped_column(String(32), default="")
    consumption_known: Mapped[bool | None] = mapped_column(Boolean, nullable=True)  # True: the provider confirmed it counted; False: it did not; None: unknown
    error_code: Mapped[str] = mapped_column(String(40), default="")
    __table_args__ = (Index("ix_provider_ledger_window", "provider", "operation", "account_key", "reserved_at"),
                      Index("ix_provider_ledger_job", "job_id"))


class ProviderState(Base):
    """Per provider and credential identity: what the account is entitled to (learned from the provider), what the operator turned off, and the last thing the provider said."""
    __tablename__ = "provider_state"
    provider: Mapped[str] = mapped_column(String(40))
    account_key: Mapped[str] = mapped_column(String(24), default="anon")
    learned_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)   # {operation: [{"window": "rolling:60", "limit": 4, "remaining": 2, "reset_at": iso, "source": "headers"}]}
    blocked_until: Mapped[datetime | None] = ts(nullable=True, default=False)
    blocked_status: Mapped[str] = mapped_column(String(24), default="")
    disabled: Mapped[bool] = mapped_column(Boolean, default=False)
    disabled_reason: Mapped[str] = mapped_column(String(120), default="")
    verified_state: Mapped[str] = mapped_column(String(20), default="")        # "" | verified | rejected | plan_restricted | wrong_format
    verified_at: Mapped[datetime | None] = ts(nullable=True, default=False)
    last_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    last_error: Mapped[str] = mapped_column(String(200), default="")
    last_response_at: Mapped[datetime | None] = ts(nullable=True, default=False)
    updated_at: Mapped[datetime] = ts()
    __table_args__ = (PrimaryKeyConstraint("provider", "account_key"),)
