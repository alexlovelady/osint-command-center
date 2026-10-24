"""Adapter contract (spec 5.3). Adapters are pure collectors: they return drafts; persistence/provenance is done by core."""
from __future__ import annotations

import hashlib
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol

from pydantic import BaseModel, Field

from ..policy.ssrf import SafeHttp

OPERATION_CLASSES = ("passive", "public_site_query", "active", "local_only")
HEALTH_STATES = ("healthy", "disabled", "not_installed", "requires_key", "rate_limited", "unavailable",
                 "degraded", "unsupported")


class Target(BaseModel):
    type: str
    raw: str
    canonical: str


class AdapterManifest(BaseModel):
    id: str
    name: str
    version: str
    supported_target_types: list[str]
    operation_class: str  # passive | public_site_query | active | local_only
    needs_network: bool
    api_key_name: str | None = None
    rate_limit_per_minute: int | None = None
    timeout_seconds: int = Field(default=45, ge=1, le=600)
    license: str | None = None
    disciplines: list[str] = Field(default_factory=lambda: ["OSINT"])
    access_class: str = "PUBLIC"
    terms_url: str | None = None
    endpoints: list[str] = Field(default_factory=list)  # shown in the pre-run preview
    description: str = ""
    install_hint: str | None = None
    default_selected: bool = True  # False: shown in the preview but only runs when explicitly chosen


class RawArtifact(BaseModel):
    name: str
    content: bytes
    mime_type: str = "application/json"
    source_url: str | None = None
    http_status: int | None = None
    published_at: datetime | None = None
    note: str = ""


class EntityRef(BaseModel):
    type: str
    key: str
    display: str | None = None


class FindingDraft(BaseModel):
    subject: EntityRef
    predicate: str
    value: Any
    confidence: str = "unknown"  # unknown|low|medium|high
    confidence_reason: str = ""
    artifact_index: int = 0
    source_published_at: datetime | None = None


class RelationshipDraft(BaseModel):
    from_entity: EntityRef
    to_entity: EntityRef
    relation_type: str
    confidence: str = "unknown"
    confidence_reason: str = ""
    artifact_index: int = 0


class AdapterResult(BaseModel):
    adapter_id: str
    status: str  # success | partial | skipped | error | rate_limited
    artifacts: list[RawArtifact] = Field(default_factory=list)
    findings: list[FindingDraft] = Field(default_factory=list)
    relationships: list[RelationshipDraft] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    error_code: str | None = None
    retryable: bool = False
    retry_after_seconds: int | None = None


@dataclass
class AdapterContext:
    http: SafeHttp
    dns_query: Callable[[str, str], Awaitable[list[str]]] | None = None
    now: Callable[[], datetime] = lambda: datetime.now(UTC)
    config: dict[str, Any] = field(default_factory=dict)
    secret: Callable[[str], str | None] = lambda name: None  # OS-keyring lookup, injected by the app


class IntelAdapter(Protocol):
    manifest: AdapterManifest

    async def health(self) -> dict: ...
    async def run(self, target: Target, ctx: AdapterContext) -> AdapterResult: ...


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def skipped(adapter_id: str, code: str, warning: str) -> AdapterResult:
    return AdapterResult(adapter_id=adapter_id, status="skipped", error_code=code, warnings=[warning])


def parse_utc(s: str | None) -> datetime | None:
    """Parse an ISO-8601 string from a source. Missing zone => UTC (documented assumption); unparseable => None."""
    if not s:
        return None
    try:
        dt = datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
