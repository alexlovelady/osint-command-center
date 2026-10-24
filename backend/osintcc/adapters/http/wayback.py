"""Wayback Machine CDX adapter: existence/timing of archived captures for a domain (passive, public)."""
from __future__ import annotations

import json
from datetime import UTC, datetime
from urllib.parse import quote

from ...policy.ssrf import DestinationDenied
from ..base import (
    AdapterContext,
    AdapterManifest,
    AdapterResult,
    EntityRef,
    FindingDraft,
    RawArtifact,
    Target,
)

LIMIT = 200


def _ts(s: str) -> datetime | None:
    try:
        return datetime.strptime(s, "%Y%m%d%H%M%S").replace(tzinfo=UTC)
    except ValueError:
        return None


class WaybackAdapter:
    manifest = AdapterManifest(
        id="wayback", name="Internet Archive Wayback (CDX)", version="1.0.0",
        supported_target_types=["domain", "url"], operation_class="passive", needs_network=True,
        rate_limit_per_minute=20, timeout_seconds=45, license="Archive metadata via CDX API; honour archive.org terms",
        terms_url="https://archive.org/about/terms.php",
        endpoints=["https://web.archive.org/cdx/search/cdx?url=<target>&output=json"],
        description="When (and how often) the target was captured by the Internet Archive. "
                    "Captures show what the archive saw, not what is live now.")

    async def health(self) -> dict:
        return {"status": "healthy", "version": self.manifest.version,
                "detail": "built-in HTTP adapter; remote availability is not guaranteed"}

    async def run(self, target: Target, ctx: AdapterContext) -> AdapterResult:
        aid = self.manifest.id
        key = target.canonical
        q = quote(key if target.type == "domain" else key.split("://", 1)[1], safe="")
        url = (f"https://web.archive.org/cdx/search/cdx?url={q}&output=json&limit={LIMIT}"
               "&fl=timestamp,original,statuscode,mimetype,digest&collapse=timestamp:6")
        try:
            res = await ctx.http.get(url)
        except DestinationDenied as exc:
            return AdapterResult(adapter_id=aid, status="error", error_code="policy_denied", warnings=[str(exc)])
        except Exception as exc:
            return AdapterResult(adapter_id=aid, status="error", error_code="network_error", retryable=True,
                                 warnings=[f"{type(exc).__name__}: {exc}"])
        if res.status == 429:
            return AdapterResult(adapter_id=aid, status="rate_limited", error_code="rate_limited", retryable=True,
                                 retry_after_seconds=90)
        if res.status != 200:
            return AdapterResult(adapter_id=aid, status="error", error_code=f"http_{res.status}",
                                 retryable=res.status >= 500, warnings=[f"CDX HTTP {res.status}"])
        try:
            rows = json.loads(res.body or b"[]")
            assert isinstance(rows, list)
        except (ValueError, AssertionError):
            return AdapterResult(adapter_id=aid, status="error", error_code="parse_error",
                                 artifacts=[RawArtifact(name="wayback-unparsed.bin", content=res.body,
                                                        source_url=res.url, http_status=res.status)],
                                 warnings=["CDX response was not the expected JSON array"])
        art = RawArtifact(name=f"wayback-{key[:60]}.json", content=res.body, source_url=res.url, http_status=200)
        data = rows[1:] if rows and rows[0] and rows[0][0] == "timestamp" else rows
        subject = EntityRef(type="url" if target.type == "url" else "domain", key=key, display=key)
        reason = "Capture index entry from the Internet Archive CDX API"
        findings: list[FindingDraft] = []
        stamps = sorted(r[0] for r in data if r)
        if stamps:
            first, last = _ts(stamps[0]), _ts(stamps[-1])
            findings += [
                FindingDraft(subject=subject, predicate="archive.first_capture", value=first.isoformat() if first else stamps[0],
                             confidence="high", confidence_reason=reason, source_published_at=first),
                FindingDraft(subject=subject, predicate="archive.latest_capture_in_sample",
                             value=last.isoformat() if last else stamps[-1], confidence="high",
                             confidence_reason=reason, source_published_at=last),
                FindingDraft(subject=subject, predicate="archive.capture_months_sampled", value=len(stamps),
                             confidence="high", confidence_reason=reason + " (collapsed to one per month, capped)"),
            ]
        warnings = ["No captures found; the archive not holding a page says nothing about whether it exists."] \
            if not stamps else []
        if len(data) >= LIMIT:
            warnings.append(f"Result capped at {LIMIT} entries; earlier/later captures may exist.")
        return AdapterResult(adapter_id=aid, status="success", artifacts=[art], findings=findings, warnings=warnings)
