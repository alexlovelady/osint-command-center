"""crt.sh adapter: Certificate Transparency names for a domain (public CT data)."""
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

MAX_NAMES = 500


class CrtShAdapter:
    manifest = AdapterManifest(
        id="crtsh", name="crt.sh certificate transparency", version="1.0.0",
        supported_target_types=["domain", "email"], operation_class="passive", needs_network=True,
        rate_limit_per_minute=6, timeout_seconds=60, license="Public CT log data via crt.sh (no availability SLA)",
        terms_url="https://crt.sh/", endpoints=["https://crt.sh/?q=%25.<domain>&output=json"],
        description="Hostnames seen in publicly logged certificates. Service is often slow or unavailable.")

    async def health(self) -> dict:
        return {"status": "healthy", "version": self.manifest.version,
                "detail": "built-in HTTP adapter; remote availability is not guaranteed"}

    async def run(self, target: Target, ctx: AdapterContext) -> AdapterResult:
        domain = target.canonical.split("@", 1)[1] if target.type == "email" else target.canonical
        aid = self.manifest.id
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        try:
            res = await ctx.http.get(url)
        except DestinationDenied as exc:
            return AdapterResult(adapter_id=aid, status="error", error_code="policy_denied", warnings=[str(exc)])
        except Exception as exc:
            return AdapterResult(adapter_id=aid, status="error", error_code="network_error", retryable=True,
                                 warnings=[f"{type(exc).__name__}: {exc}"])
        if res.status == 429:
            return AdapterResult(adapter_id=aid, status="rate_limited", error_code="rate_limited", retryable=True,
                                 retry_after_seconds=120)
        if res.status != 200:
            return AdapterResult(adapter_id=aid, status="error", error_code=f"http_{res.status}",
                                 retryable=res.status >= 500, warnings=[f"crt.sh HTTP {res.status}"])
        try:
            rows = json.loads(res.body or b"[]")
            assert isinstance(rows, list)
        except (ValueError, AssertionError):
            return AdapterResult(adapter_id=aid, status="error", error_code="parse_error",
                                 artifacts=[RawArtifact(name="crtsh-unparsed.bin", content=res.body,
                                                        source_url=res.url, http_status=res.status)],
                                 warnings=["crt.sh response was not the expected JSON list"])
        art = RawArtifact(name=f"crtsh-{domain}.json", content=res.body, source_url=res.url, http_status=200)
        subject = EntityRef(type="domain", key=domain, display=domain)
        names: dict[str, dict] = {}
        for row in rows:
            for nm in str(row.get("name_value", "")).splitlines():
                nm = nm.strip().lower().lstrip("*.")
                if nm and (nm == domain or nm.endswith("." + domain)):
                    cur = names.setdefault(nm, {"first": row.get("not_before"), "certs": set()})
                    cur["certs"].add(row.get("id"))
                    if row.get("not_before") and (not cur["first"] or row["not_before"] < cur["first"]):
                        cur["first"] = row["not_before"]
        warnings: list[str] = []
        ordered = sorted(names)
        if len(ordered) > MAX_NAMES:
            warnings.append(f"Truncated to {MAX_NAMES} of {len(ordered)} names.")
            ordered = ordered[:MAX_NAMES]
        reason = "Name appears in a publicly logged certificate; certificate existence does not prove the host is live"
        findings, rels = [], []
        for nm in ordered:
            info = names[nm]
            if nm != domain:
                other = EntityRef(type="domain", key=nm, display=nm)
                rels.append(RelationshipDraft(from_entity=other, to_entity=subject, relation_type="subdomain_of",
                                              confidence="medium", confidence_reason=reason))
                findings.append(FindingDraft(subject=other, predicate="ct.seen_in_certificate",
                                             value={"cert_count": len(info["certs"]),
                                                    "earliest_not_before": info["first"]},
                                             confidence="medium", confidence_reason=reason,
                                             source_published_at=parse_utc(info["first"])))
        findings.append(FindingDraft(subject=subject, predicate="ct.distinct_names",
                                     value=len(ordered), confidence="medium", confidence_reason=reason))
        if not rows:
            warnings.append("crt.sh returned no certificates; absence in CT is not proof of non-existence.")
        return AdapterResult(adapter_id=aid, status="success", artifacts=[art], findings=findings,
                             relationships=rels, warnings=warnings)
