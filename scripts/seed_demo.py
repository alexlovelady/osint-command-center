"""Seed a running dev backend with SYNTHETIC demo data (fixtures from tests/). Dev only.

    OSINTCC_SESSION_TOKEN=dev-token-local-only uv run python scripts/seed_demo.py http://127.0.0.1:8791 <case_id>
"""
import os
import sys
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests" / "fixtures"))
import synthetic
import synthetic_intel as si

base, cid = sys.argv[1], sys.argv[2]
c = httpx.Client(base_url=base + "/api/v1", headers={"Authorization": "Bearer " + os.environ.get("OSINTCC_SESSION_TOKEN", "dev-token-local-only")}, timeout=60)


def ingest(name, data, **kw):
    q = "&".join(f"{k}={v}" for k, v in kw.items())
    r = c.post(f"/cases/{cid}/ingest?filename={name}&consent_confirmed=true&{q}", content=data)
    print(name, r.status_code, r.json().get("kind", r.json().get("message")))


ingest("photo.jpg", si.jpeg_with_gps(48.8584, 2.2945, hacc=5))
ingest("photo2.jpg", si.jpeg_with_gps(51.5007, -0.1246))
ingest("capture.pcap", si.pcap())
ingest("bundle.stix.json", si.stix_bundle())
ingest("widget.cdx.json", si.cyclonedx())
ingest("run1.tlm.csv", si.telemetry_csv())
ingest("t.sigmf", synthetic.sigmf_archive())
ingest("temp.csv", synthetic.sensor_csv())
ingest("firmware.bin", si.firmware())
# analysis objects
fs = c.get(f"/cases/{cid}/findings?limit=500").json()["items"]
reg = next((f for f in fs if f["predicate"] == "rdap.registrar"), fs[0])
claim = c.post("/claims/from-finding", json={"finding_id": reg["id"]}).json()
ents = c.get(f"/cases/{cid}/entities?limit=1000").json()["items"]
dom = next(e for e in ents if e["type"] == "domain")
evs = c.get(f"/cases/{cid}/evidence").json()["items"]
for v, e in (("Registrar A", evs[0]["id"]), ("Registrar B", evs[1]["id"])):
    c.post("/claims", json={"case_id": cid, "subject_entity_id": dom["id"], "predicate": "reported_registrar", "value": v, "sources": [{"evidence_id": e}]})
c.post("/requirements", json={"case_id": cid, "question": "Who operates the infrastructure behind example.com?", "priority": "high"})
c.post("/hypotheses", json={"case_id": cid, "statement": "The domain is operated by its registrant"})
tpl = next(t for t in c.get("/workflow-templates").json()["items"] if t["id"] == "passive-domain-overview")
c.post("/workflows", json={"case_id": cid, "definition": tpl})
c.post(f"/cases/{cid}/human-sources", json={"alias": "Witness A", "consent": {"basis": "informed_consent", "authorizing_party": "the source (verbal, field note 1)", "scope": ["interview"]}})
print("seeded", cid)
