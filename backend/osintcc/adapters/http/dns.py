"""DNS adapter: A/AAAA/NS/MX/TXT/CNAME via dnspython with a hard timeout."""
from __future__ import annotations

import json

from ..base import (
    AdapterContext,
    AdapterManifest,
    AdapterResult,
    EntityRef,
    FindingDraft,
    RawArtifact,
    RelationshipDraft,
    Target,
)

RTYPES = ("A", "AAAA", "NS", "MX", "CNAME", "TXT")


async def default_dns_query(name: str, rtype: str) -> list[str]:
    import dns.asyncresolver
    import dns.exception
    import dns.resolver

    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = 8.0
    try:
        answer = await resolver.resolve(name, rtype)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    return sorted(r.to_text() for r in answer)


class DnsAdapter:
    manifest = AdapterManifest(
        id="dns", name="DNS records", version="1.0.0", supported_target_types=["domain", "email"],
        operation_class="passive", needs_network=True, rate_limit_per_minute=60, timeout_seconds=30,
        license="dnspython (ISC)", endpoints=["system DNS resolver"],
        description="Resolves common record types through the configured system resolver.")

    async def health(self) -> dict:
        try:
            import dns  # noqa: F401
            return {"status": "healthy", "version": self.manifest.version}
        except ImportError:
            return {"status": "unavailable", "detail": "dnspython not importable"}

    async def run(self, target: Target, ctx: AdapterContext) -> AdapterResult:
        domain = target.canonical.split("@", 1)[1] if target.type == "email" else target.canonical
        query = ctx.dns_query or default_dns_query
        records: dict[str, list[str]] = {}
        warnings: list[str] = []
        for rt in RTYPES:
            try:
                records[rt] = await query(domain, rt)
            except Exception as exc:
                records[rt] = []
                warnings.append(f"{rt} lookup failed: {type(exc).__name__}")
        if all(not v for v in records.values()) and warnings:
            return AdapterResult(adapter_id="dns", status="error", error_code="resolver_error", retryable=True,
                                 warnings=warnings)
        payload = json.dumps({"domain": domain, "records": records}, sort_keys=True, indent=2).encode()
        art = RawArtifact(name=f"dns-{domain}.json", content=payload, source_url=f"dns://{domain}")
        subject = EntityRef(type="domain", key=domain, display=domain)
        findings: list[FindingDraft] = []
        rels: list[RelationshipDraft] = []
        reason = "Answer from configured recursive resolver at retrieval time"
        for rt, vals in records.items():
            for v in vals:
                findings.append(FindingDraft(subject=subject, predicate=f"dns.{rt.lower()}", value=v,
                                             confidence="high", confidence_reason=reason))
                if rt in ("A", "AAAA"):
                    rels.append(RelationshipDraft(
                        from_entity=subject, to_entity=EntityRef(type="ip", key=v, display=v),
                        relation_type="resolves_to", confidence="high", confidence_reason=reason))
                elif rt in ("NS", "CNAME", "MX"):
                    host = v.split()[-1].rstrip(".").lower()
                    if "." in host:
                        rel = {"NS": "uses_nameserver", "CNAME": "alias_of", "MX": "mail_handled_by"}[rt]
                        rels.append(RelationshipDraft(
                            from_entity=subject, to_entity=EntityRef(type="domain", key=host, display=host),
                            relation_type=rel, confidence="high", confidence_reason=reason))
        status = "success" if not warnings else "partial"
        if not any(records.values()):
            warnings.append("No records returned (NXDOMAIN or empty zone); this is an observation, not proof of absence.")
        return AdapterResult(adapter_id="dns", status=status, artifacts=[art], findings=findings,
                             relationships=rels, warnings=warnings)
