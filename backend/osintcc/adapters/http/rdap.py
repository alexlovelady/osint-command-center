"""RDAP adapter: IANA bootstrap -> authoritative registry RDAP server (RFC 9082/9083)."""
from __future__ import annotations

import json

from ...policy.ssrf import DestinationDenied
from ..base import (
    AdapterContext,
    AdapterManifest,
    AdapterResult,
    EntityRef,
    FindingDraft,
    RawArtifact,
    RelationshipDraft,
    Target,
    parse_utc,
)

BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"


class RdapAdapter:
    manifest = AdapterManifest(
        id="rdap", name="RDAP domain registration", version="1.0.0", supported_target_types=["domain", "email"],
        operation_class="passive", needs_network=True, rate_limit_per_minute=30, timeout_seconds=30,
        license="Public registry data (RFC 9083); respect registry terms",
        terms_url="https://www.icann.org/rdap", endpoints=[BOOTSTRAP_URL, "<registry RDAP server per TLD>"],
        description="Registrar, status, lifecycle dates and nameservers from the authoritative registry.")

    def __init__(self) -> None:
        self._bootstrap: dict | None = None

    async def health(self) -> dict:
        return {"status": "healthy", "version": self.manifest.version, "detail": "built-in HTTP adapter"}

    async def _server_for(self, tld: str, ctx: AdapterContext) -> tuple[str | None, RawArtifact | None]:
        if self._bootstrap is None:
            res = await ctx.http.get(BOOTSTRAP_URL)
            if res.status != 200:
                raise RuntimeError(f"bootstrap HTTP {res.status}")
            self._bootstrap = json.loads(res.body)
        for tlds, urls in self._bootstrap.get("services", []):
            if tld in tlds and urls:
                https = [u for u in urls if u.startswith("https://")]
                return (https or urls)[0], None
        return None, None

    async def run(self, target: Target, ctx: AdapterContext) -> AdapterResult:
        domain = target.canonical.split("@", 1)[1] if target.type == "email" else target.canonical
        aid = self.manifest.id
        try:
            base, _ = await self._server_for(domain.rsplit(".", 1)[-1], ctx)
            if not base:
                return AdapterResult(adapter_id=aid, status="skipped", error_code="no_rdap_server",
                                     warnings=[f"No RDAP server is registered for TLD .{domain.rsplit('.', 1)[-1]}"])
            url = f"{base.rstrip('/')}/domain/{domain}"
            res = await ctx.http.get(url, headers={"Accept": "application/rdap+json, application/json"})
        except DestinationDenied as exc:
            return AdapterResult(adapter_id=aid, status="error", error_code="policy_denied", warnings=[str(exc)])
        except Exception as exc:  # network/parse errors are transient by default
            return AdapterResult(adapter_id=aid, status="error", error_code="network_error", retryable=True,
                                 warnings=[f"{type(exc).__name__}: {exc}"])
        if res.status == 429:
            ra = res.headers.get("retry-after", "")
            return AdapterResult(adapter_id=aid, status="rate_limited", error_code="rate_limited", retryable=True,
                                 retry_after_seconds=int(ra) if ra.isdigit() else 60)
        if res.status == 404:
            art = RawArtifact(name="rdap-404.json", content=res.body or b"{}", source_url=res.url, http_status=404)
            return AdapterResult(adapter_id=aid, status="success", artifacts=[art],
                                 warnings=["Registry reports no record for this domain (it may be unregistered)."])
        if res.status != 200:
            return AdapterResult(adapter_id=aid, status="error", error_code=f"http_{res.status}",
                                 retryable=res.status >= 500, warnings=[f"RDAP HTTP {res.status}"])
        try:
            data = json.loads(res.body)
        except ValueError:
            return AdapterResult(adapter_id=aid, status="error", error_code="parse_error",
                                 artifacts=[RawArtifact(name="rdap-unparsed.bin", content=res.body,
                                                        source_url=res.url, http_status=res.status)],
                                 warnings=["RDAP response was not JSON (output contract changed?)"])
        art = RawArtifact(name=f"rdap-{domain}.json", content=res.body, mime_type="application/rdap+json",
                          source_url=res.url, http_status=200)
        subject = EntityRef(type="domain", key=domain, display=domain)
        f: list[FindingDraft] = []
        rels: list[RelationshipDraft] = []
        reason = "Authoritative registry RDAP response"
        for status in data.get("status", []) or []:
            f.append(FindingDraft(subject=subject, predicate="rdap.status", value=status, confidence="high",
                                  confidence_reason=reason))
        for ev in data.get("events", []) or []:
            action, date = ev.get("eventAction"), ev.get("eventDate")
            if action and date:
                f.append(FindingDraft(subject=subject, predicate=f"rdap.event.{action.replace(' ', '_')}",
                                      value=date, confidence="high", confidence_reason=reason,
                                      source_published_at=parse_utc(date)))
        if data.get("handle"):
            f.append(FindingDraft(subject=subject, predicate="rdap.handle", value=data["handle"],
                                  confidence="high", confidence_reason=reason))
        for ent in data.get("entities", []) or []:
            if "registrar" in (ent.get("roles") or []):
                name = None
                for item in (ent.get("vcardArray") or [None, []])[1]:
                    if item and item[0] == "fn":
                        name = item[3]
                name = name or ent.get("handle")
                if name:
                    f.append(FindingDraft(subject=subject, predicate="rdap.registrar", value=name,
                                          confidence="high", confidence_reason=reason))
        for ns in data.get("nameservers", []) or []:
            nm = (ns.get("ldhName") or "").lower().rstrip(".")
            if nm:
                other = EntityRef(type="domain", key=nm, display=nm)
                rels.append(RelationshipDraft(from_entity=subject, to_entity=other, relation_type="uses_nameserver",
                                              confidence="high", confidence_reason=reason))
                f.append(FindingDraft(subject=subject, predicate="rdap.nameserver", value=nm, confidence="high",
                                      confidence_reason=reason))
        return AdapterResult(adapter_id=aid, status="success", artifacts=[art], findings=f, relationships=rels,
                             warnings=["Registrant contact data is often redacted; absence is not evidence."])
