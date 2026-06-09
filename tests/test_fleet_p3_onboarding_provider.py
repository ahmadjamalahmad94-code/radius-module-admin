"""CHR Fleet Phase 3 — group 1 (P3-T1 onboarding + P3-T6 provider CRUD).

Covers:
  * provider_service CRUD + cost-model validation + delete-guard,
  * the provider JSON routes,
  * the onboarding state machine driven with in-memory collaborator fakes
    (the real P3-T2/T3/T4 modules are not on main yet),
  * the onboarding routes, incl. graceful 503 when a dependency is missing and a
    check that the secret-bearing script is never returned in a response.
"""
from __future__ import annotations

import pytest

from app import create_app, seed_defaults
from app.config import TestingConfig
from app.extensions import db
from fleet.registry import provider_service as psvc
from fleet.registry.models_chr import FleetChrNode, FleetProvider
from fleet.registry.onboarding_service import (
    OnboardingError,
    OnboardingService,
    PushResult,
    WgKeyPair,
)


# ──────────────────────────── app / auth fixtures ────────────────────────────
@pytest.fixture()
def app():
    app = create_app(TestingConfig)
    # The phase-gate integrator registers these in app/__init__.py; tests wire
    # them onto a throwaway app so we never touch that shared file here.
    # Post Phase-3 gate, create_app() already registers the fleet blueprints
    # (admin_fleet_provider, admin_fleet_onboarding, …) — no manual wiring here.
    with app.app_context():
        db.create_all()
        seed_defaults(app)
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def auth_client(app, client):
    from app.models import Admin

    admin = Admin.query.filter_by(username="admin").first() or Admin.query.first()
    with client.session_transaction() as sess:
        sess["admin_id"] = admin.id
    return client


# ──────────────────────────── collaborator fakes ─────────────────────────────
class FakeKeys:
    def __init__(self):
        self._n = 0

    def generate_keypair(self) -> WgKeyPair:
        self._n += 1
        return WgKeyPair(private_key=f"PRIVKEY{self._n}", public_key=f"PUBKEY{self._n}")


class FakeVault:
    def __init__(self):
        self.store: dict[str, str] = {}

    def store_secret(self, hint: str, secret: str) -> str:
        ref = f"vault://{hint}#{len(self.store)}"
        self.store[ref] = secret
        return ref

    def fetch_secret(self, ref: str) -> str:
        return self.store[ref]


class FakeRenderer:
    def render(self, bindings: dict) -> str:
        return "\n".join(f"# {k}={v}" for k, v in bindings.items())


class FakePusher:
    def __init__(self, ok: bool = True, detail: str = ""):
        self.ok = ok
        self.detail = detail
        self.calls: list = []

    def push(self, job, reach: dict, script: str) -> PushResult:
        self.calls.append((job, reach, script))
        return PushResult(ok=self.ok, detail=self.detail)


def _service(ok: bool = True) -> OnboardingService:
    return OnboardingService(
        key_provider=FakeKeys(),
        vault=FakeVault(),
        renderer=FakeRenderer(),
        pusher=FakePusher(ok=ok),
        config={"CHR_SHARED_SECRET": "fleet-secret", "PANEL_WG_PUBKEY": "PANELPUB"},
    )


FORM = {
    "provider": "Contabo",
    "name": "contabo-de-01",
    "public_ip": "203.0.113.11",
    "cost_model": "metered",
    "max_sessions": 500,
    "link_speed_mbps": 1000,
    "monthly_cap_tb": 30,
    "price_per_tb": 5.0,
    "overage_allowed": False,
}


# ════════════════════════════ provider service ═══════════════════════════════
def test_provider_open_flattens_cost(app):
    p = psvc.create_provider(name="OpenCo", cost_model="open",
                             price_per_tb=9, monthly_cap_tb=100, overage_allowed=True)
    assert p.cost_model == "open"
    assert float(p.price_per_tb) == 0.0
    assert p.monthly_cap_tb is None
    assert p.overage_allowed is False


def test_provider_metered_keeps_price_and_cap(app):
    p = psvc.create_provider(name="MeterCo", cost_model="metered",
                             price_per_tb=5, monthly_cap_tb=30)
    assert p.cost_model == "metered"
    assert float(p.price_per_tb) == 5.0
    assert float(p.monthly_cap_tb) == 30.0


def test_provider_validation_errors(app):
    with pytest.raises(psvc.ProviderError):
        psvc.create_provider(name="", cost_model="open")
    with pytest.raises(psvc.ProviderError):
        psvc.create_provider(name="X", cost_model="bogus")
    # metered without a price is rejected
    with pytest.raises(psvc.ProviderError):
        psvc.create_provider(name="NoPrice", cost_model="metered", price_per_tb=None)
    # overage allowed but no overage price
    with pytest.raises(psvc.ProviderError):
        psvc.create_provider(name="Over", cost_model="metered", price_per_tb=5,
                             overage_allowed=True, overage_price_per_tb=None)


def test_provider_duplicate_name(app):
    psvc.create_provider(name="Dup", cost_model="open")
    with pytest.raises(psvc.ProviderNameTaken):
        psvc.create_provider(name="Dup", cost_model="open")


def test_provider_update_open_to_metered_normalizes(app):
    p = psvc.create_provider(name="Flip", cost_model="metered", price_per_tb=4)
    psvc.update_provider(p.id, cost_model="open")
    db.session.refresh(p)
    assert p.cost_model == "open"
    assert float(p.price_per_tb) == 0.0
    assert p.monthly_cap_tb is None


def test_provider_delete_guard_when_nodes_attached(app):
    p = psvc.create_provider(name="HasNodes", cost_model="open")
    node = FleetChrNode(
        provider_id=p.id, name="n1", public_ip="10.0.0.1",
        wg_mgmt_ip="10.99.0.50", wg_mgmt_pubkey="k",
        max_sessions=10, link_speed_mbps=100,
    )
    db.session.add(node)
    db.session.commit()
    with pytest.raises(psvc.ProviderInUse):
        psvc.delete_provider(p.id)
    # remove the node → delete now succeeds
    db.session.delete(node)
    db.session.commit()
    psvc.delete_provider(p.id)
    assert psvc.get_provider(p.id) is None


# ════════════════════════════ provider routes ════════════════════════════════
def test_provider_routes_crud(auth_client):
    r = auth_client.post("/admin/fleet/providers",
                         json={"name": "Hetzner", "cost_model": "metered",
                               "price_per_tb": 3, "monthly_cap_tb": 20})
    assert r.status_code == 201, r.get_data(as_text=True)
    pid = r.get_json()["provider"]["id"]

    r = auth_client.get("/admin/fleet/providers")
    assert r.status_code == 200
    assert any(p["name"] == "Hetzner" for p in r.get_json()["providers"])

    r = auth_client.post(f"/admin/fleet/providers/{pid}", json={"price_per_tb": 7})
    assert r.status_code == 200
    assert r.get_json()["provider"]["price_per_tb"] == 7.0

    r = auth_client.post(f"/admin/fleet/providers/{pid}/delete")
    assert r.status_code == 200
    assert auth_client.get(f"/admin/fleet/providers/{pid}").status_code == 404


def test_provider_routes_validation_and_conflict(auth_client):
    assert auth_client.post("/admin/fleet/providers",
                            json={"name": "X", "cost_model": "bogus"}).status_code == 400
    auth_client.post("/admin/fleet/providers", json={"name": "Once", "cost_model": "open"})
    assert auth_client.post("/admin/fleet/providers",
                            json={"name": "Once", "cost_model": "open"}).status_code == 409


def test_provider_routes_require_login(client):
    # No session → login_required redirects (302), not a 200/JSON.
    assert client.get("/admin/fleet/providers").status_code in (301, 302)


# ════════════════════════════ onboarding service ═════════════════════════════
def test_onboarding_happy_path_stepwise(app):
    svc = _service()
    job = svc.create_draft(FORM)
    assert job.status == "draft"
    assert FleetProvider.query.filter_by(name="Contabo").one()  # provider created

    svc.generate_keys(job)
    assert job.status == "keys_generated"
    node = db.session.get(FleetChrNode, job.chr_id)
    assert node is not None and node.wg_mgmt_pubkey == "PUBKEY1"
    assert node.wg_mgmt_ip == "10.99.0.11"  # allocated from the pool
    # job stores vault REFS + pubkeys, never the private keys
    assert "PRIVKEY" not in (job.wg_keypair_ref or "")
    assert "mgmt_privkey_ref" in job.wg_keypair_ref

    job2, script = svc.render_script(job)
    assert job.status == "script_generated"
    assert job.generated_script_ref.startswith("sha256:")
    # rendered script embeds the per-CHR bindings incl. the fetched private key
    assert "ROUTER_IDENTITY=contabo-de-01" in script
    assert "WG_MGMT_PRIVKEY=PRIVKEY1" in script
    assert "CHR_SHARED_SECRET=fleet-secret" in script

    svc.push(job, reach={"host": "1.2.3.4", "user": "admin"})
    assert job.status == "pushed"


def test_onboarding_push_failure_marks_failed_then_retry(app):
    svc = _service(ok=False)
    job = svc.create_draft(FORM)
    svc.generate_keys(job)
    svc.render_script(job)
    with pytest.raises(OnboardingError):
        svc.push(job, reach={"host": "1.2.3.4"})
    assert job.status == "failed"
    assert "failed_reason" in (job.verify_report or {})
    # retry edge: failed → script_generated
    svc.retry(job)
    assert job.status == "script_generated"


def test_onboarding_illegal_transition(app):
    svc = _service()
    job = svc.create_draft(FORM)
    # cannot push straight from draft (must go through keys + script first)
    with pytest.raises(OnboardingError):
        svc.push(job, reach={})
    assert job.status == "draft"


def test_mgmt_ip_allocation_is_unique(app):
    svc = _service()
    j1 = svc.create_draft(FORM)
    svc.generate_keys(j1)
    j2 = svc.create_draft({**FORM, "name": "contabo-de-02", "public_ip": "203.0.113.12"})
    svc.generate_keys(j2)
    ips = {db.session.get(FleetChrNode, j1.chr_id).wg_mgmt_ip,
           db.session.get(FleetChrNode, j2.chr_id).wg_mgmt_ip}
    assert ips == {"10.99.0.11", "10.99.0.12"}


def test_onboarding_provision_pipeline(app):
    svc = _service()
    job = svc.provision(FORM, reach={"host": "1.2.3.4"})
    assert job.status == "pushed"


# ════════════════════════════ onboarding routes ══════════════════════════════
def test_onboarding_draft_route(auth_client):
    r = auth_client.post("/admin/fleet/onboarding/jobs", json=FORM)
    assert r.status_code == 201, r.get_data(as_text=True)
    body = r.get_json()
    assert body["job"]["status"] == "draft"


def test_onboarding_generate_keys_with_real_dependencies(auth_client):
    # Post the Phase-3 gate, the real wg_keys + secrets_vault modules are merged,
    # so generate-keys runs the real flow (no 503). Proves the dependency wiring.
    r = auth_client.post("/admin/fleet/onboarding/jobs", json=FORM)
    jid = r.get_json()["job"]["id"]
    r = auth_client.post(f"/admin/fleet/onboarding/{jid}/generate-keys")
    assert r.status_code == 200, r.get_data(as_text=True)
    assert r.get_json()["job"]["status"] == "keys_generated"


def test_onboarding_routes_full_flow_with_injected_fakes(auth_client, monkeypatch):
    shared = _service()
    monkeypatch.setattr("fleet.registry.routes_onboarding.build_service", lambda: shared)

    jid = auth_client.post("/admin/fleet/onboarding/jobs", json=FORM).get_json()["job"]["id"]

    r = auth_client.post(f"/admin/fleet/onboarding/{jid}/generate-keys")
    assert r.status_code == 200 and r.get_json()["job"]["status"] == "keys_generated"

    r = auth_client.post(f"/admin/fleet/onboarding/{jid}/render-script")
    assert r.status_code == 200 and r.get_json()["job"]["status"] == "script_generated"
    # SECURITY: the secret-bearing script must NEVER be returned in the response.
    assert "PRIVKEY" not in r.get_data(as_text=True)

    r = auth_client.post(f"/admin/fleet/onboarding/{jid}/push", json={"reach": {"host": "1.2.3.4"}})
    assert r.status_code == 200 and r.get_json()["job"]["status"] == "pushed"
