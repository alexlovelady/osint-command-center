"""SEC EDGAR submissions adapter (official public data; the SEC requires a descriptive User-Agent with contact info)."""
from __future__ import annotations

import json

from ...ingest.fin import edgar_filing_url
from ...policy.ssrf import DestinationDenied
from ...quota.credentials import validate_contact
from ..base import (
    AdapterContext,
    AdapterManifest,
    AdapterResult,
    EntityRef,
    FindingDraft,
    RawArtifact,
    RelationshipDraft,
    Target,
    skipped,
)


class EdgarAdapter:
    manifest = AdapterManifest(
        id="sec_edgar", name="SEC EDGAR (company filings)", version="1.0.0", supported_target_types=["cik"],
        operation_class="passive", needs_network=True, api_key_name=None, rate_limit_per_minute=30, timeout_seconds=30,
        license="US government public data; follow https://www.sec.gov/os/accessing-edgar-data",
        terms_url="https://www.sec.gov/os/accessing-edgar-data", endpoints=["https://data.sec.gov/submissions/CIK<10 digits>.json"],
        description="Official filing index for a company identified by CIK. Requires your contact string in Settings "
                    "(SEC fair-access policy). Matches by CIK only, never by company name.",
        install_hint="Set 'edgar_contact' in Settings to 'Your Name your@email' (sent as the User-Agent, per SEC policy).")

    async def health(self) -> dict:
        return {"status": "healthy", "version": self.manifest.version,
                "detail": "built-in adapter; needs the 'edgar_contact' setting before it can run"}

    async def run(self, target: Target, ctx: AdapterContext) -> AdapterResult:
        aid = self.manifest.id
        err, ua = validate_contact(ctx.config.get("edgar_user_agent"))
        if err:
            return skipped(aid, "requires_config", f"The SEC requires a contact (your name and email) in the User-Agent. {err} Set it in Settings; no request was made.")
        cik = target.canonical.split(":", 1)[1]
        url = f"https://data.sec.gov/submissions/CIK{cik}.json"
        try:
            res = await ctx.http.get(url, headers={"User-Agent": ua, "Accept": "application/json"})
        except DestinationDenied as exc:
            return AdapterResult(adapter_id=aid, status="error", error_code="policy_denied", warnings=[str(exc)])
        except Exception as exc:
            return AdapterResult(adapter_id=aid, status="error", error_code="network_error", retryable=True,
                                 warnings=[f"{type(exc).__name__}: {exc}"])
        if res.status == 429:
            return AdapterResult(adapter_id=aid, status="rate_limited", error_code="rate_limited", retryable=True,
                                 retry_after_seconds=120)
        if res.status == 404:
            return AdapterResult(adapter_id=aid, status="success", warnings=[f"No EDGAR record for CIK {cik}."],
                                 artifacts=[RawArtifact(name=f"edgar-{cik}-404.json", content=res.body or b"{}", source_url=url,
                                                        http_status=404)])
        if res.status != 200:
            return AdapterResult(adapter_id=aid, status="error", error_code=f"http_{res.status}",
                                 retryable=res.status >= 500, warnings=[f"EDGAR HTTP {res.status}"])
        try:
            d = json.loads(res.body)
            recent = d["filings"]["recent"]
            acc, forms, dates = recent["accessionNumber"], recent["form"], recent["filingDate"]
            docs = recent.get("primaryDocument", [])
        except (ValueError, KeyError, TypeError):
            return AdapterResult(adapter_id=aid, status="error", error_code="parse_error",
                                 artifacts=[RawArtifact(name="edgar-unparsed.bin", content=res.body, source_url=url,
                                                        http_status=200)],
                                 warnings=["EDGAR response did not match the expected structure (contract changed?)"])
        art = RawArtifact(name=f"edgar-{cik}.json", content=res.body, source_url=url, http_status=200)
        company = EntityRef(type="company", key=target.canonical, display=f"{d.get('name', cik)} ({target.canonical})")
        why = "Official SEC EDGAR submissions record, matched by CIK"
        findings = [FindingDraft(subject=company, predicate=f"edgar.{k}", value=d.get(src), confidence="high", confidence_reason=why)
                    for k, src in (("name", "name"), ("sic", "sic"), ("sic_description", "sicDescription"),
                                   ("state_of_incorporation", "stateOfIncorporation"), ("tickers", "tickers")) if d.get(src)]
        rels = []
        for i in range(min(len(acc), 50)):
            f = EntityRef(type="filing", key=f"sec:{acc[i]}", display=f"{forms[i]} {dates[i]} ({acc[i]})")
            url_f = edgar_filing_url(cik, acc[i], docs[i] if i < len(docs) else None)
            rels.append(RelationshipDraft(from_entity=company, to_entity=f, relation_type="filed", confidence="high",
                                          confidence_reason=f"{why}; {url_f}"))
        return AdapterResult(adapter_id=aid, status="success", artifacts=[art], findings=findings, relationships=rels,
                             warnings=["Only the most recent 50 filings are linked."] if len(acc) > 50 else [])
