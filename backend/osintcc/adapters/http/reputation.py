"""Third-party reputation/exposure adapters: VirusTotal, urlscan.io (existing public results only), Shodan.

All three are read-only lookups of data the provider already holds. They never upload files, never submit scans, and
report `requires_key` (without any request) when the OS credential store has no key.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote

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
    skipped,
)


def _requires_key(aid: str, key: str) -> AdapterResult:
    return skipped(aid, "requires_key", f"No '{key}' API key is stored in the OS credential store; no request was made. "
                   f"Add one in Settings (POST /secrets/{key}).")


async def _get(ctx: AdapterContext, aid: str, url: str, headers: dict[str, str] | None = None):
    try:
        res = await ctx.http.get(url, headers=headers)
    except DestinationDenied as exc:
        return None, AdapterResult(adapter_id=aid, status="error", error_code="policy_denied", warnings=[str(exc)])
    except Exception as exc:
        return None, AdapterResult(adapter_id=aid, status="error", error_code="network_error", retryable=True,
                                   warnings=[f"{type(exc).__name__}: {exc}"])
    if res.status == 429:
        ra = res.headers.get("retry-after", "")
        return None, AdapterResult(adapter_id=aid, status="rate_limited", error_code="rate_limited", retryable=True,
                                   retry_after_seconds=int(ra) if ra.isdigit() else 120)
    if res.status in (401, 403):
        return None, AdapterResult(adapter_id=aid, status="skipped", error_code="requires_key",
                                   warnings=[f"The provider rejected the API key (HTTP {res.status}); it may be wrong or revoked."])
    return res, None


def _dt(ts: Any) -> datetime | None:
    try:
        return datetime.fromtimestamp(int(ts), UTC)
    except (TypeError, ValueError, OSError):
        return None


class VirusTotalAdapter:
    manifest = AdapterManifest(
        id="virustotal", default_selected=False, name="VirusTotal (reputation lookup)", version="1.0.0", supported_target_types=["domain", "ip"],
        operation_class="passive", needs_network=True, api_key_name="virustotal", rate_limit_per_minute=4, timeout_seconds=30,
        license="Provider terms apply; free API keys are rate-limited and non-commercial",
        terms_url="https://docs.virustotal.com/reference/overview", endpoints=["https://www.virustotal.com/api/v3/{domains|ip_addresses}/<target>"],
        description="Existing public reputation summary. Never uploads files or submits URLs.",
        install_hint="Store a VirusTotal API key via the secrets endpoint (name: virustotal).")

    async def health(self) -> dict:
        return {"status": "healthy", "version": self.manifest.version, "detail": "needs an API key in the OS credential store"}

    async def run(self, target: Target, ctx: AdapterContext) -> AdapterResult:
        aid = self.manifest.id
        key = ctx.secret("virustotal")
        if not key:
            return _requires_key(aid, "virustotal")
        kind = "ip_addresses" if target.type == "ip" else "domains"
        url = f"https://www.virustotal.com/api/v3/{kind}/{quote(target.canonical, safe='')}"
        res, err = await _get(ctx, aid, url, {"x-apikey": key})
        if err:
            return err
        if res.status == 404:
            return AdapterResult(adapter_id=aid, status="success", warnings=["VirusTotal has no record for this target."],
                                 artifacts=[RawArtifact(name="vt-404.json", content=res.body or b"{}", source_url=url, http_status=404)])
        if res.status != 200:
            return AdapterResult(adapter_id=aid, status="error", error_code=f"http_{res.status}", retryable=res.status >= 500,
                                 warnings=[f"VirusTotal HTTP {res.status}"])
        try:
            attrs = json.loads(res.body)["data"]["attributes"]
        except (ValueError, KeyError, TypeError):
            return AdapterResult(adapter_id=aid, status="error", error_code="parse_error", warnings=["unexpected VirusTotal structure"],
                                 artifacts=[RawArtifact(name="vt-unparsed.bin", content=res.body, source_url=url, http_status=200)])
        art = RawArtifact(name=f"vt-{target.canonical}.json", content=res.body, source_url=url, http_status=200)
        subj = EntityRef(type=target.type, key=target.canonical, display=target.canonical)
        why = "Provider-aggregated engine verdicts at the stated analysis time; engines disagree and false positives occur"
        stats = attrs.get("last_analysis_stats", {})
        when = _dt(attrs.get("last_analysis_date"))
        f = [FindingDraft(subject=subj, predicate="vt.last_analysis_stats", value=stats, confidence="medium",
                          confidence_reason=why, source_published_at=when)]
        if "reputation" in attrs:
            f.append(FindingDraft(subject=subj, predicate="vt.reputation", value=attrs["reputation"], confidence="low",
                                  confidence_reason="Community score; subjective"))
        if attrs.get("categories"):
            f.append(FindingDraft(subject=subj, predicate="vt.categories", value=attrs["categories"], confidence="low",
                                  confidence_reason="Third-party categorisation"))
        w = ["Reputation is a provider opinion at a point in time, not proof of malicious intent."]
        if stats.get("malicious", 0) == 0 and stats.get("suspicious", 0) == 0:
            w.append("No engine flagged this target; that is not proof it is safe.")
        return AdapterResult(adapter_id=aid, status="success", artifacts=[art], findings=f, warnings=w)


class UrlscanAdapter:
    manifest = AdapterManifest(
        id="urlscan", default_selected=False, name="urlscan.io (existing public results)", version="1.0.0", supported_target_types=["domain"],
        operation_class="passive", needs_network=True, api_key_name="urlscan", rate_limit_per_minute=20, timeout_seconds=30,
        license="urlscan.io terms apply", terms_url="https://urlscan.io/docs/api/",
        endpoints=["https://urlscan.io/api/v1/search/?q=domain:<target>"],
        description="Searches scans other people already made public. Never submits a scan.")

    async def health(self) -> dict:
        return {"status": "healthy", "version": self.manifest.version, "detail": "works without a key at a lower rate limit"}

    async def run(self, target: Target, ctx: AdapterContext) -> AdapterResult:
        aid = self.manifest.id
        url = f"https://urlscan.io/api/v1/search/?q=domain:{quote(target.canonical, safe='')}&size=20"
        key = ctx.secret("urlscan")
        res, err = await _get(ctx, aid, url, {"API-Key": key} if key else None)
        if err:
            return err
        if res.status != 200:
            return AdapterResult(adapter_id=aid, status="error", error_code=f"http_{res.status}", retryable=res.status >= 500,
                                 warnings=[f"urlscan HTTP {res.status}"])
        try:
            d = json.loads(res.body)
            results = d["results"]
        except (ValueError, KeyError, TypeError):
            return AdapterResult(adapter_id=aid, status="error", error_code="parse_error", warnings=["unexpected urlscan structure"],
                                 artifacts=[RawArtifact(name="urlscan-unparsed.bin", content=res.body, source_url=url, http_status=200)])
        art = RawArtifact(name=f"urlscan-{target.canonical}.json", content=res.body, source_url=url, http_status=200)
        subj = EntityRef(type="domain", key=target.canonical, display=target.canonical)
        why = "Result of a scan someone else ran and made public; shows what the scanner saw at that time"
        f = [FindingDraft(subject=subj, predicate="urlscan.public_scan_count", value=int(d.get("total", len(results))),
                          confidence="medium", confidence_reason=why)]
        rels: list[RelationshipDraft] = []
        ips = {}
        for r in results:
            pg = r.get("page", {})
            if pg.get("ip"):
                ips[pg["ip"]] = pg.get("country")
        for ip, cc in list(ips.items())[:20]:
            other = EntityRef(type="ip", key=ip, display=ip)
            rels.append(RelationshipDraft(from_entity=subj, to_entity=other, relation_type="seen_hosted_on", confidence="medium",
                                          confidence_reason=why))
            f.append(FindingDraft(subject=other, predicate="urlscan.country_hint", value=cc, confidence="low",
                                  confidence_reason="Geolocation of an IP is approximate and often wrong"))
        if results:
            f.append(FindingDraft(subject=subj, predicate="urlscan.latest_scan", value=results[0].get("task", {}).get("time"),
                                  confidence="medium", confidence_reason=why,
                                  source_published_at=None))
        return AdapterResult(adapter_id=aid, status="success", artifacts=[art], findings=f, relationships=rels,
                             warnings=[] if results else ["No public scans found; this does not mean the domain was never scanned."])


class ShodanAdapter:
    manifest = AdapterManifest(
        id="shodan", default_selected=False, name="Shodan (host exposure index)", version="1.0.0", supported_target_types=["ip"],
        operation_class="passive", needs_network=True, api_key_name="shodan", rate_limit_per_minute=30, timeout_seconds=30,
        license="Shodan API terms apply (key and plan dependent)", terms_url="https://www.shodan.io/",
        endpoints=["https://api.shodan.io/shodan/host/<ip>"],
        description="What Shodan previously observed on an IP. Does not scan the target.")

    async def health(self) -> dict:
        return {"status": "healthy", "version": self.manifest.version, "detail": "needs an API key in the OS credential store"}

    async def run(self, target: Target, ctx: AdapterContext) -> AdapterResult:
        aid = self.manifest.id
        key = ctx.secret("shodan")
        if not key:
            return _requires_key(aid, "shodan")
        clean = f"https://api.shodan.io/shodan/host/{target.canonical}"
        res, err = await _get(ctx, aid, f"{clean}?key={quote(key, safe='')}")  # Shodan only supports the key as a query param
        if err:
            return err
        if res.status == 404:
            return AdapterResult(adapter_id=aid, status="success", warnings=["Shodan has no information for this IP."],
                                 artifacts=[RawArtifact(name="shodan-404.json", content=res.body or b"{}", source_url=clean, http_status=404)])
        if res.status != 200:
            return AdapterResult(adapter_id=aid, status="error", error_code=f"http_{res.status}", retryable=res.status >= 500,
                                 warnings=[f"Shodan HTTP {res.status}"])
        try:
            d = json.loads(res.body)
        except ValueError:
            return AdapterResult(adapter_id=aid, status="error", error_code="parse_error", warnings=["Shodan returned non-JSON"])
        art = RawArtifact(name=f"shodan-{target.canonical}.json", content=res.body, source_url=clean, http_status=200)  # key-free URL
        subj = EntityRef(type="ip", key=target.canonical, display=target.canonical)
        why = "Shodan's own earlier observation; the service may have changed since the stated time"
        f = [FindingDraft(subject=subj, predicate="shodan.open_ports", value=sorted(d.get("ports", [])), confidence="medium",
                          confidence_reason=why, source_published_at=None)]
        for fld in ("org", "isp", "os"):
            if d.get(fld):
                f.append(FindingDraft(subject=subj, predicate=f"shodan.{fld}", value=d[fld], confidence="medium", confidence_reason=why))
        if d.get("hostnames"):
            f.append(FindingDraft(subject=subj, predicate="shodan.hostnames", value=d["hostnames"], confidence="low",
                                  confidence_reason="Reverse-DNS style data; unverified"))
        if d.get("vulns"):
            f.append(FindingDraft(subject=subj, predicate="shodan.reported_vulns", value=sorted(d["vulns"])[:50], confidence="low",
                                  confidence_reason="Inferred from banners; frequently false positives"))
        return AdapterResult(adapter_id=aid, status="success", artifacts=[art], findings=f,
                             warnings=["Indexed data can be stale; this adapter did not touch the host."])
