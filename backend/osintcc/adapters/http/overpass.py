"""OpenStreetMap Overpass adapter: named features near a coordinate (bounded, low volume, ODbL attribution)."""
from __future__ import annotations

import json
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
)

RADIUS_M = 200
MAX_FEATURES = 50


class OverpassAdapter:
    manifest = AdapterManifest(
        id="overpass", name="OpenStreetMap (Overpass)", version="1.0.0", supported_target_types=["coordinates"],
        operation_class="passive", needs_network=True, rate_limit_per_minute=6, timeout_seconds=40,
        license="ODbL 1.0 - attribution: © OpenStreetMap contributors", terms_url="https://operations.osmfoundation.org/policies/",
        endpoints=["https://overpass-api.de/api/interpreter?data=<bounded query>"],
        description=f"Named OSM features within {RADIUS_M} m of a point (max {MAX_FEATURES}). Crowd-sourced; may be incomplete or wrong.")

    async def health(self) -> dict:
        return {"status": "healthy", "version": self.manifest.version, "detail": "public Overpass instance; be gentle (6/min)"}

    async def run(self, target: Target, ctx: AdapterContext) -> AdapterResult:
        aid = self.manifest.id
        lat, lon = target.canonical.split(",")
        q = (f"[out:json][timeout:25];(node(around:{RADIUS_M},{lat},{lon})[name];way(around:{RADIUS_M},{lat},{lon})[name];);"
             f"out center {MAX_FEATURES};")
        url = f"https://overpass-api.de/api/interpreter?data={quote(q, safe='')}"
        try:
            res = await ctx.http.get(url)
        except DestinationDenied as exc:
            return AdapterResult(adapter_id=aid, status="error", error_code="policy_denied", warnings=[str(exc)])
        except Exception as exc:
            return AdapterResult(adapter_id=aid, status="error", error_code="network_error", retryable=True,
                                 warnings=[f"{type(exc).__name__}: {exc}"])
        if res.status in (429, 504):
            return AdapterResult(adapter_id=aid, status="rate_limited", error_code="rate_limited", retryable=True, retry_after_seconds=60)
        if res.status != 200:
            return AdapterResult(adapter_id=aid, status="error", error_code=f"http_{res.status}", retryable=res.status >= 500,
                                 warnings=[f"Overpass HTTP {res.status}"])
        try:
            els = json.loads(res.body)["elements"]
        except (ValueError, KeyError, TypeError):
            return AdapterResult(adapter_id=aid, status="error", error_code="parse_error", warnings=["unexpected Overpass structure"],
                                 artifacts=[RawArtifact(name="overpass-unparsed.bin", content=res.body, source_url=url, http_status=200)])
        art = RawArtifact(name=f"overpass-{lat}_{lon}.json", content=res.body, source_url=url, http_status=200)
        origin = EntityRef(type="place", key=f"point:{target.canonical}", display=f"point {target.canonical}")
        why = "Crowd-sourced OpenStreetMap data (ODbL); positions and tags may be outdated or inaccurate"
        f, rels = [], []
        for e in els[:MAX_FEATURES]:
            tags = e.get("tags", {})
            ent = EntityRef(type="place", key=f"osm:{e.get('type', 'node')}/{e.get('id')}",
                            display=f"{tags.get('name', 'unnamed')} (osm {e.get('type')}/{e.get('id')})")
            c = e if "lat" in e else e.get("center", {})
            f.append(FindingDraft(subject=ent, predicate="osm.feature", confidence="low", confidence_reason=why,
                                  value={"tags": {k: v for k, v in tags.items() if k in ("name", "amenity", "shop", "building", "tourism", "man_made", "highway")},
                                         "lat": c.get("lat"), "lon": c.get("lon")}))
            rels.append(RelationshipDraft(from_entity=origin, to_entity=ent, relation_type="near", confidence="low",
                                          confidence_reason=f"within {RADIUS_M} m by OSM geometry; proximity does not imply a relationship"))
        return AdapterResult(adapter_id=aid, status="success", artifacts=[art], findings=f, relationships=rels,
                             warnings=["Attribution required: © OpenStreetMap contributors (ODbL)."
                                       + ("" if els else " No named features nearby; OSM coverage varies.")])
