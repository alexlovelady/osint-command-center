"""Seed a running dev backend with a SYNTHETIC Target Profile example (fictional person, example.com, no real data). Dev only.

    OSINTCC_SESSION_TOKEN=dev-token-local-only uv run python scripts/seed_profile_demo.py http://127.0.0.1:8791

Creates a people case 'Jane Example (synthetic)', a self-audit subject, an authorization, inputs, one claim awaiting review and one recorded exposure.
It runs no research and contacts nothing.
"""
import os
import sys
from datetime import UTC, datetime, timedelta

import httpx

base = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8791"
c = httpx.Client(base_url=base + "/api/v1", headers={"Authorization": "Bearer " + os.environ.get("OSINTCC_SESSION_TOKEN", "dev-token-local-only")}, timeout=60)


def post(path: str, body: dict) -> dict:
    r = c.post(path, json=body)
    r.raise_for_status()
    return r.json()


case = post("/cases", {"title": "Jane Example (synthetic)", "category": "people", "purpose": "synthetic demonstration of a self-audit; fictional person"})
sub = post(f"/cases/{case['id']}/subjects", {"display_name": "Jane Example", "mode": "self"})
post(f"/subjects/{sub['id']}/identifiers", {"kind": "domain", "value": "example.com"})
post(f"/subjects/{sub['id']}/identifiers", {"kind": "username", "value": "jane_example_demo"})
post(f"/subjects/{sub['id']}/consent", {"verification_method": "email_confirmation", "verifier": "demo operator", "source_classes": ["public_passive", "exposure_check", "image_analysis"],
                                         "permitted_purposes": ["synthetic demo"], "expires_at": (datetime.now(UTC) + timedelta(days=14)).isoformat()})
post(f"/subjects/{sub['id']}/claims", {"field": "employer", "value": "Example Corp (fictional)"})
post(f"/subjects/{sub['id']}/exposure", {"cls": "social_oversharing", "provider": "manual", "status": "not_assessed", "verification_basis": "manual_review", "descriptor": "Not checked yet"})
print(f"open #/case/{case['id']} in the app: the Target profile screen shows an unreviewed claim and an unassessed exposure; nothing has been collected.")
