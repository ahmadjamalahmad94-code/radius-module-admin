"""Phase-3 gate integration — the parallel sub-teams wired together.

Exercises the onboarding flow with the REAL collaborators resolved through the
default adapters (no fakes for keys/vault/render), proving the cross-module
contract holds after the four P3 branches merged:

  * wg_keys.generate_keypair()  → WgKeypair (mapped to WgKeyPair)
  * secrets_vault.store_secret(owner,purpose,plaintext,kind)/retrieve_secret → VaultRef/str
  * script_render.render_from_bindings(bindings) under StrictUndefined → full script
  * bootstrap_push.push_to_chr(job, BootstrapTarget, script) → advances job to pushed

Only the network transport is faked (registered via the module's own
register_transport hook) — everything else is the merged production code.
"""
from __future__ import annotations

import pytest

from app import create_app, seed_defaults
from app.config import TestingConfig
from app.extensions import db

# Import the real modules so their models (e.g. secrets_vault.ChrSecret →
# fleet_chr_secrets) register on the metadata before create_all().
import fleet.registry.secrets_vault  # noqa: F401
from fleet.registry import bootstrap_push
from fleet.registry.models_chr import FleetChrNode
from fleet.registry.onboarding_service import OnboardingError, OnboardingService

FORM = {
    "provider": "Contabo",
    "name": "contabo-de-01",
    "public_ip": "203.0.113.11",
    "cost_model": "metered",
    "max_sessions": 500,
    "link_speed_mbps": 1000,
    "monthly_cap_tb": 30,
    "price_per_tb": 5.0,
}

_FLEET_CONST = {
    "PANEL_WG_PUBKEY": "PANELPUB", "PANEL_WG_ENDPOINT": "panel:51820", "PANEL_WG_ADDR": "10.99.0.1",
    "PROXY_WG_PUBKEY": "PROXYPUB", "PROXY_WG_ENDPOINT": "proxy:51821", "PROXY_WG_ADDR": "10.98.0.1",
    "CHR_SHARED_SECRET": "fleet-secret", "SSTP_CERT_NAME": "c", "IKE_CERT_NAME": "c",
    "CLIENT_SUPERNET": "10.0.0.0/8", "DNS_PUSH": "1.1.1.1", "GW_LOCAL_ADDR": "10.0.0.1",
    "WAN_IFACE": "ether1",
}


@pytest.fixture()
def app():
    app = create_app(TestingConfig)
    with app.app_context():
        db.create_all()
        seed_defaults(app)
        yield app
        db.session.remove()
        db.drop_all()


class _FakeTransport:
    """Stands in for the (Phase-7) real RouterOS transport so push completes."""

    def __init__(self, target):
        self.target = target

    def push_script(self, script: str):
        return bootstrap_push.TransportResult(ok=True, output="applied")

    def close(self):
        pass


def test_onboarding_real_collaborators_render_and_push(app):
    bootstrap_push.register_transport("api", lambda target: _FakeTransport(target))
    svc = OnboardingService(config=_FLEET_CONST)  # real key/vault/render/push adapters

    job = svc.create_draft(FORM, auto_advance=False)
    assert job.status == "draft"

    svc.generate_keys(job)  # real wg_keys + real secrets_vault
    assert job.status == "keys_generated"
    node = db.session.get(FleetChrNode, job.chr_id)
    assert node is not None and node.wg_mgmt_pubkey  # real Curve25519 public key
    # private keys are vaulted (refs only on the job), never plaintext
    assert "mgmt_privkey_ref" in job.wg_keypair_ref
    assert "PRIV" not in job.wg_keypair_ref

    job2, script = svc.render_script(job)  # real script_render under StrictUndefined
    assert job.status == "script_generated"
    # Reaching here proves every template binding was supplied (StrictUndefined
    # would have raised otherwise). Spot-check real RouterOS markers + identity.
    assert "wg-mgmt" in script
    assert "contabo-de-01" in script
    assert "10.98.0." in script  # the derived wg-data address binding

    svc.push(job, reach={"host": "10.0.0.9", "username": "admin", "password": "x"})
    assert job.status == "pushed"  # bootstrap_push advanced it; service didn't double-advance


def test_push_failure_via_real_pusher_marks_failed(app):
    class _FailTransport(_FakeTransport):
        def push_script(self, script):
            return bootstrap_push.TransportResult(ok=False, error="auth_failed")

    bootstrap_push.register_transport("api", lambda target: _FailTransport(target))
    svc = OnboardingService(config=_FLEET_CONST)

    job = svc.create_draft({**FORM, "name": "contabo-de-09", "public_ip": "203.0.113.19"}, auto_advance=False)
    svc.generate_keys(job)
    svc.render_script(job)
    with pytest.raises(OnboardingError):
        svc.push(job, reach={"host": "10.0.0.9"})
    assert job.status == "failed"
