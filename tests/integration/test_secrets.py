from __future__ import annotations

import json
import secrets as pysecrets

import httpx
import pytest
from osintcc.config import Settings
from osintcc.db.models import AuditEvent, Setting
from osintcc.main import create_app
from osintcc.secrets_store import SecretStore

KEY = pysecrets.token_bytes(32)


class FakeKeyring:
    def __init__(self, broken=False):
        self.data, self.broken = {}, broken

    def _chk(self):
        if self.broken:
            raise RuntimeError("no backend")

    def get_password(self, s, u):
        self._chk()
        return self.data.get((s, u))

    def set_password(self, s, u, p):
        self._chk()
        self.data[(s, u)] = p

    def delete_password(self, s, u):
        self._chk()
        self.data.pop((s, u))


@pytest.fixture
async def api(tmp_path, monkeypatch):
    kr = FakeKeyring()
    monkeypatch.setattr(SecretStore, "_keyring", staticmethod(lambda: kr))
    s = Settings(data_dir=tmp_path / "d", vault_encryption="required", run_scheduler=False)
    app = create_app(s, vault_key=KEY)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1/api/v1",
                                     headers={"Authorization": f"Bearer {s.session_token}"}) as c:
            c.app, c.kr = app, kr
            yield c


async def test_catalog_set_use_and_remove_without_ever_echoing_the_value(api):
    items = {i["provider"]: i for i in (await api.get("/secrets")).json()["items"]}
    assert {"virustotal", "shodan", "censys", "urlscan", "opencorporates"} <= set(items) and not any(i["set"] for i in items.values())
    assert items["censys"]["format"].startswith("API_ID:API_SECRET") and "censys" in items["censys"]["used_by"]
    r = await api.post("/secrets/shodan", json={"value": "  SUPERSECRET-123  "})
    assert r.status_code == 200 and r.json() == {"provider": "shodan", "stored": True, "store": "os-keyring"} and "SUPERSECRET" not in r.text
    assert api.kr.data[("osintcc", "shodan")] == "SUPERSECRET-123"                      # trimmed, stored in the credential store
    assert api.app.state.core.secrets.get("shodan") == "SUPERSECRET-123"                # what adapters receive
    after = {i["provider"]: i for i in (await api.get("/secrets")).json()["items"]}
    assert after["shodan"]["set"] is True and "SUPERSECRET" not in json.dumps(after)
    with api.app.state.core.sm() as db:
        assert "SUPERSECRET" not in json.dumps([e.metadata_json for e in db.query(AuditEvent)])
    d = await api.delete("/secrets/shodan")
    assert d.json()["removed"] is True and api.app.state.core.secrets.get("shodan") is None
    assert (await api.post("/secrets/Bad Name!", json={"value": "x"})).status_code in (404, 422)
    assert (await api.post("/secrets/shodan", json={"value": ""})).status_code == 422


async def test_without_an_os_credential_store_the_key_is_sealed_in_the_encrypted_database(api):
    api.kr.broken = True
    r = await api.post("/secrets/virustotal", json={"value": "VT-KEY-ABC"})
    assert r.json()["store"] == "encrypted-database"
    with api.app.state.core.sm() as db:
        blob = db.get(Setting, "secret:virustotal").value_json
    assert "VT-KEY-ABC" not in blob and api.app.state.core.secrets.get("virustotal") == "VT-KEY-ABC"
    # a sealed row cannot be re-labelled as another provider
    with api.app.state.core.sm() as db:
        db.merge(Setting(key="secret:shodan", value_json=blob))
        db.commit()
    assert api.app.state.core.secrets.get("shodan") is None
    assert (await api.delete("/secrets/virustotal")).json()["removed"] is True and api.app.state.core.secrets.get("virustotal") is None


async def test_no_store_and_no_key_refuses_to_save(tmp_path, monkeypatch):
    monkeypatch.setattr(SecretStore, "_keyring", staticmethod(lambda: FakeKeyring(broken=True)))
    s = Settings(data_dir=tmp_path / "x", vault_encryption="off", run_scheduler=False)
    app = create_app(s)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1/api/v1",
                                     headers={"Authorization": f"Bearer {s.session_token}"}) as c:
            r = await c.post("/secrets/shodan", json={"value": "k"})
            assert r.status_code == 503 and r.json()["code"] == "secret_store_unavailable"


async def test_only_admins_can_list_or_change_keys(api):
    from osintcc.db.models import User
    with api.app.state.core.sm() as db:
        db.add(User(id="u2", display_name="Other"))
        db.commit()
    api.app.state.core.tokens["tok2"] = "u2"
    h = {"Authorization": "Bearer tok2"}
    assert (await api.get("/secrets", headers=h)).status_code == 403
    assert (await api.post("/secrets/shodan", json={"value": "k"}, headers=h)).status_code == 403
    assert (await api.delete("/secrets/shodan", headers=h)).status_code == 403
