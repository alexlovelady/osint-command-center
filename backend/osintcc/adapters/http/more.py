"""Additional read-only lookups: GDELT (news mentions), OpenCorporates (company registry search), Censys (host index).

Same rules as the other HTTP adapters: only data the provider already holds, no scans or submissions, keys come from the
OS credential store and are never written to artifacts, and a missing key means NO request is made.
"""
from __future__ import annotations

import base64
import json
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote

from ...quota.credentials import censys_kind
from ..base import (
    AdapterContext,
    AdapterManifest,
    AdapterResult,
    EntityRef,
    FindingDraft,
    RawArtifact,
    Target,
    skipped,
)
from .reputation import _get, _requires_key

MAX_ARTICLES = 25


def _gdelt_time(s: Any) -> datetime | None:
    try:
        return datetime.strptime(str(s), "%Y%m%dT%H%M%SZ").replace(tzinfo=UTC)
    except ValueError:
        return None


class GdeltAdapter:
    manifest = AdapterManifest(
        id="gdelt", default_selected=False, name="GDELT (news mentions of a domain)", version="1.0.0", supported_target_types=["domain"],
        operation_class="passive", needs_network=True, rate_limit_per_minute=10, timeout_seconds=40,
        license="GDELT is open for use with attribution (https://www.gdeltproject.org/about.html)",
        terms_url="https://www.gdeltproject.org/about.html",
        endpoints=["https://api.gdeltproject.org/api/v2/doc/doc?query=domain:<target>&mode=artlist&format=json"],
        description=f"Recent news articles GDELT indexed from this domain (max {MAX_ARTICLES}). Machine-collected; coverage and tone scores are unreliable.")

    async def health(self) -> dict:
        return {"status": "healthy", "version": self.manifest.version, "detail": "public API, no key; keep to a few requests a minute"}

    async def run(self, target: Target, ctx: AdapterContext) -> AdapterResult:
        aid = self.manifest.id
        url = (f"https://api.gdeltproject.org/api/v2/doc/doc?query={quote('domain:' + target.canonical, safe='')}"
               f"&mode=artlist&maxrecords={MAX_ARTICLES}&format=json&sort=datedesc")
        res, err = await _get(ctx, aid, url)
        if err:
            return err
        if res.status != 200:
            return AdapterResult(adapter_id=aid, status="error", error_code=f"http_{res.status}", retryable=res.status >= 500,
                                 warnings=[f"GDELT HTTP {res.status}"])
        try:
            arts = json.loads(res.body or b"{}").get("articles") or []
        except ValueError:
            return AdapterResult(adapter_id=aid, status="error", error_code="parse_error", warnings=["GDELT returned non-JSON"],
                                 artifacts=[RawArtifact(name="gdelt-unparsed.bin", content=res.body, source_url=url, http_status=200)])
        art = RawArtifact(name=f"gdelt-{target.canonical}.json", content=res.body, source_url=url, http_status=200)
        subj = EntityRef(type="domain", key=target.canonical, display=target.canonical)
        why = "Machine-indexed article metadata; GDELT does not vouch for the content and may mis-attribute it"
        f = [FindingDraft(subject=subj, predicate="gdelt.recent_article_count", value=len(arts), confidence="low", confidence_reason=why)]
        for a in arts[:MAX_ARTICLES]:
            if isinstance(a, dict) and a.get("url"):
                f.append(FindingDraft(subject=subj, predicate="gdelt.article", value={"title": str(a.get("title", ""))[:200], "url": a["url"],
                                                                                      "language": a.get("language"), "country": a.get("sourcecountry")},
                                      confidence="low", confidence_reason=why, source_published_at=_gdelt_time(a.get("seendate"))))
        return AdapterResult(adapter_id=aid, status="success", artifacts=[art], findings=f,
                             warnings=[] if arts else ["GDELT returned no articles; this is not evidence the domain is unmentioned."])


class OpenCorporatesAdapter:
    manifest = AdapterManifest(
        id="opencorporates", default_selected=False, name="OpenCorporates (company registry search)", version="1.0.0",
        supported_target_types=["company"], operation_class="passive", needs_network=True, api_key_name="opencorporates",
        rate_limit_per_minute=10, timeout_seconds=30, license="OpenCorporates terms apply (share-alike open data; API key required)",
        terms_url="https://opencorporates.com/info/licence", endpoints=["https://api.opencorporates.com/v0.4/companies/search?q=<name>"],
        description="Registry records whose name matches. A name match is a lead: unrelated companies share names.",
        install_hint="Store an OpenCorporates API token via the secrets endpoint (name: opencorporates).")

    async def health(self) -> dict:
        return {"status": "healthy", "version": self.manifest.version, "detail": "needs an API token in the OS credential store"}

    async def run(self, target: Target, ctx: AdapterContext) -> AdapterResult:
        aid = self.manifest.id
        key = ctx.secret("opencorporates")
        if not key:
            return _requires_key(aid, "opencorporates")
        clean = f"https://api.opencorporates.com/v0.4/companies/search?q={quote(target.canonical, safe='')}&per_page=10"
        res, err = await _get(ctx, aid, f"{clean}&api_token={quote(key, safe='')}")  # the API only accepts the token as a query parameter
        if err:
            return err
        if res.status != 200:
            return AdapterResult(adapter_id=aid, status="error", error_code=f"http_{res.status}", retryable=res.status >= 500,
                                 warnings=[f"OpenCorporates HTTP {res.status}"])
        try:
            companies = json.loads(res.body)["results"]["companies"]
        except (ValueError, KeyError, TypeError):
            return AdapterResult(adapter_id=aid, status="error", error_code="parse_error", warnings=["unexpected OpenCorporates structure"])
        art = RawArtifact(name="opencorporates-search.json", content=res.body, source_url=clean, http_status=200)  # token-free URL
        why = "Registry record matched by name only; identity of the company with the person of interest is NOT established"
        f: list[FindingDraft] = []
        for c in companies[:10]:
            co = c.get("company", {}) if isinstance(c, dict) else {}
            if not co.get("company_number") or not co.get("jurisdiction_code"):
                continue
            ref = EntityRef(type="company", key=f"{co['jurisdiction_code']}:{co['company_number']}", display=str(co.get("name", ""))[:200])
            f.append(FindingDraft(subject=ref, predicate="opencorporates.record", confidence="medium", confidence_reason=why,
                                  value={k: co.get(k) for k in ("name", "current_status", "incorporation_date", "company_type",
                                                                "registered_address_in_full", "opencorporates_url")}))
        return AdapterResult(adapter_id=aid, status="success", artifacts=[art], findings=f,
                             warnings=["Name matches are leads; confirm identity with registry numbers and independent sources."]
                             + ([] if f else ["No registry records matched."]))


class CensysAdapter:
    """Censys host lookup. Two authentication paths, never mixed:
    * a Personal Access Token (the current Censys Platform): `Authorization: Bearer <token>` to api.platform.censys.io;
    * a legacy `API_ID:API_SECRET` pair (the older Search API): HTTP Basic to search.censys.io, kept only because it is a genuinely separate, still-documented path.
    A token is never turned into an ID:secret pair, and search endpoints (not part of the Free plan) are never called."""
    manifest = AdapterManifest(
        id="censys", default_selected=False, name="Censys (host lookup)", version="2.0.0", supported_target_types=["ip"],
        operation_class="passive", needs_network=True, api_key_name="censys", rate_limit_per_minute=20, timeout_seconds=30,
        license="Censys terms apply (plan dependent); the Free plan has 100 credits per month and lookup endpoints only", terms_url="https://docs.censys.com/docs/platform-credits-free-starter",
        endpoints=["https://api.platform.censys.io/v3/global/asset/host/<ip>", "https://search.censys.io/api/v2/hosts/<ip> (legacy ID-and-key pair only)"],
        description="What Censys previously observed on one IP. Does not scan the target. Costs 1 credit per lookup; Fusion never buys credits. "
                    "Credential: a Personal Access Token (preferred) or the legacy ID-and-key pair.",
        install_hint="Store a Censys Personal Access Token (Censys account menu, API Access) under the name 'censys' in Settings.")

    async def health(self) -> dict:
        return {"status": "healthy", "version": self.manifest.version, "detail": "needs a Personal Access Token (or a legacy ID-and-key pair) in the credential store; "
                "response parsing is fixture-tested, not verified against the live service"}

    async def run(self, target: Target, ctx: AdapterContext) -> AdapterResult:
        aid = self.manifest.id
        key = (ctx.secret("censys") or "").strip()
        if not key:
            return _requires_key(aid, "censys")
        kind = censys_kind(key)
        if kind == "wrong_format":
            return skipped(aid, "requires_config", "The stored Censys credential is not a Personal Access Token or an API_ID:API_SECRET pair, so no request was made. Replace it in Settings.")
        if kind == "pat":
            url = f"https://api.platform.censys.io/v3/global/asset/host/{quote(target.canonical, safe='')}"
            headers = {"Authorization": f"Bearer {key}", "Accept": "application/vnd.censys.api.v3.host.v1+json"}
        else:
            url = f"https://search.censys.io/api/v2/hosts/{quote(target.canonical, safe='')}"
            headers = {"Authorization": "Basic " + base64.b64encode(key.encode()).decode()}
        res, err = await _get(ctx, aid, url, headers)
        if err:
            return err
        if res.status == 404:
            return AdapterResult(adapter_id=aid, status="success", warnings=["Censys has no information for this IP."],
                                 artifacts=[RawArtifact(name="censys-404.json", content=res.body or b"{}", source_url=url, http_status=404)])
        if res.status != 200:
            return AdapterResult(adapter_id=aid, status="error", error_code=f"http_{res.status}", retryable=res.status >= 500,
                                 warnings=[f"Censys HTTP {res.status}"])
        try:
            data = json.loads(res.body)["result"]
            r = data.get("resource", data) if isinstance(data, dict) else {}
            assert isinstance(r, dict)
        except (ValueError, KeyError, TypeError, AssertionError):
            return AdapterResult(adapter_id=aid, status="error", error_code="parse_error", warnings=["unexpected Censys structure"],
                                 artifacts=[RawArtifact(name="censys-unparsed.bin", content=res.body, source_url=url, http_status=200)])
        art = RawArtifact(name=f"censys-{target.canonical}.json", content=res.body, source_url=url, http_status=200)
        subj = EntityRef(type="ip", key=target.canonical, display=target.canonical)
        why = "Censys's own earlier observation; services may have changed since the stated time"
        svcs = [{"port": s.get("port"), "service": s.get("service_name") or s.get("protocol"), "transport": s.get("transport_protocol")}
                for s in r.get("services", []) if isinstance(s, dict)]
        f = [FindingDraft(subject=subj, predicate="censys.services", value=svcs, confidence="medium", confidence_reason=why)]
        asys = r.get("autonomous_system") or {}
        if asys:
            f.append(FindingDraft(subject=subj, predicate="censys.autonomous_system", value={"asn": asys.get("asn"), "name": asys.get("name")},
                                  confidence="medium", confidence_reason=why))
        loc = r.get("location") or {}
        if loc.get("country_code"):
            f.append(FindingDraft(subject=subj, predicate="censys.country_hint", value=loc["country_code"], confidence="low",
                                  confidence_reason="Geolocation of an IP is approximate and often wrong"))
        return AdapterResult(adapter_id=aid, status="success", artifacts=[art], findings=f,
                             warnings=["Index data describes the past; it is not a live probe."])
