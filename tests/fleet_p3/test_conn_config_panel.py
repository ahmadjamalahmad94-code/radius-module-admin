"""feat/chr-conn-config-panel (M2) — per-CHR end-user connection config.

The «إدارة عقد البيانات» page lets the operator tune, PER CHR, the pool
range / DNS / PPP gateway+encryption / SSTP port+cert — persisted on
FleetChrNode.conn_config_json, validated server-side, and overlaid onto
the rendered script. Covers: the validation service, the GET/POST route
(super-admin + server-side validation + needs_reimport), and the
binding-overlay so the script reflects per-node choices.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.extensions import db
from app.models import Admin
from fleet.registry.models_chr import FleetChrNode, FleetProvider


# ════════════════════════════════════════════════════════════════════════
# Helpers
# ════════════════════════════════════════════════════════════════════════
def _login_super(client):
    client.post("/login", data={"username": "admin", "password": "admin12345"})
    adm = Admin.query.first()
    if adm and not adm.is_super_admin:
        adm.is_super_admin = True
        db.session.commit()


def _provider() -> FleetProvider:
    p = FleetProvider.query.first()
    if p is not None:
        return p
    p = FleetProvider(name="cc-prov", cost_model="open", price_per_tb=0,
                      overage_allowed=False, billing_cycle_day=1)
    db.session.add(p); db.session.commit()
    return p


_SEQ = [90]


def _make_node(**kw) -> FleetChrNode:
    _SEQ[0] += 1
    base = dict(
        provider_id=_provider().id,
        name=f"chr-cc-{_SEQ[0]}",
        public_ip=f"203.0.113.{_SEQ[0]}",
        wg_mgmt_ip=f"10.99.0.{_SEQ[0]}", wg_mgmt_pubkey="x" * 44,
        max_sessions=500, link_speed_mbps=1000, weight=1.0,
        enabled=True, drain=False, status="up",
    )
    base.update(kw)
    n = FleetChrNode(**base)
    db.session.add(n); db.session.commit()
    return n


# ════════════════════════════════════════════════════════════════════════
# (1) Service — defaults + validation
# ════════════════════════════════════════════════════════════════════════
class TestConnConfigService:

    def test_empty_blob_returns_defaults(self, app):
        with app.app_context():
            from app.services.node_conn_config import DEFAULTS, get_conn_config
            n = _make_node()
            cfg = get_conn_config(n)
            assert cfg["pool_ranges"] == DEFAULTS["pool_ranges"]
            assert cfg["sstp_port"] == 443
            assert cfg["sstp_cert_mode"] == "auto"

    def test_valid_update_persists_and_merges(self, app):
        with app.app_context():
            from app.services.node_conn_config import get_conn_config, set_conn_config
            n = _make_node()
            set_conn_config(n, {"pool_ranges": "10.60.0.10-10.60.0.250",
                                "dns": "9.9.9.9", "sstp_port": 8443}, commit=True)
            cfg = get_conn_config(n)
            assert cfg["pool_ranges"] == "10.60.0.10-10.60.0.250"
            assert cfg["dns"] == "9.9.9.9"
            assert cfg["sstp_port"] == 8443
            # Untouched keys keep defaults.
            assert cfg["gw_local_addr"] == "10.0.0.1"

    def test_pool_overlap_with_reserved_rejected(self, app):
        with app.app_context():
            from app.services.node_conn_config import ConnConfigError, set_conn_config
            n = _make_node()
            for bad in ("10.99.0.10-10.99.0.50",   # wg-mgmt
                        "10.98.0.10-10.98.0.50",   # wg-data
                        "10.51.0.10-10.51.0.50"):  # wg-users
                with pytest.raises(ConnConfigError):
                    set_conn_config(n, {"pool_ranges": bad})

    def test_gw_in_reserved_rejected(self, app):
        with app.app_context():
            from app.services.node_conn_config import ConnConfigError, set_conn_config
            n = _make_node()
            with pytest.raises(ConnConfigError):
                set_conn_config(n, {"gw_local_addr": "10.99.0.1"})

    def test_bad_port_rejected(self, app):
        with app.app_context():
            from app.services.node_conn_config import ConnConfigError, set_conn_config
            n = _make_node()
            with pytest.raises(ConnConfigError):
                set_conn_config(n, {"sstp_port": 70000})

    def test_custom_cert_mode_requires_name(self, app):
        with app.app_context():
            from app.services.node_conn_config import ConnConfigError, set_conn_config
            n = _make_node()
            with pytest.raises(ConnConfigError):
                set_conn_config(n, {"sstp_cert_mode": "custom", "sstp_cert_name": ""})

    def test_bad_cn_rejected(self, app):
        with app.app_context():
            from app.services.node_conn_config import ConnConfigError, set_conn_config
            n = _make_node()
            with pytest.raises(ConnConfigError):
                set_conn_config(n, {"sstp_cert_cn": 'evil" name'})


# ════════════════════════════════════════════════════════════════════════
# (2) Route — GET/POST, validation, needs_reimport
# ════════════════════════════════════════════════════════════════════════
class TestConnConfigRoute:

    GET = "/admin/fleet/data-nodes/{id}/conn-config"
    POST = "/admin/fleet/data-nodes/{id}/conn-config"

    def test_get_returns_effective_config(self, app, client):
        _login_super(client)
        n = _make_node()
        r = client.get(self.GET.format(id=n.id))
        assert r.status_code == 200
        body = r.get_json()
        assert body["ok"] is True
        assert body["config"]["sstp_port"] == 443

    def test_post_valid_sets_needs_reimport(self, app, client):
        _login_super(client)
        n = _make_node()
        assert not n.needs_reimport
        r = client.post(self.POST.format(id=n.id),
                        json={"config": {"dns": "8.8.8.8,8.8.4.4"}})
        assert r.status_code == 200
        body = r.get_json()
        assert body["ok"] is True and body["changed"] is True
        assert body["needs_reimport"] is True
        assert body["config"]["dns"] == "8.8.8.8,8.8.4.4"

    def test_post_invalid_returns_400_arabic(self, app, client):
        _login_super(client)
        n = _make_node()
        r = client.post(self.POST.format(id=n.id),
                        json={"config": {"pool_ranges": "10.99.0.10-10.99.0.20"}})
        assert r.status_code == 400
        body = r.get_json()
        assert body["ok"] is False
        assert body["error"] == "invalid_config"
        assert "محجوزة" in body["message"]
        # Rejected change must NOT flip needs_reimport.
        db.session.expire_all()
        fresh = db.session.get(FleetChrNode, n.id)
        assert not fresh.needs_reimport

    def test_unknown_node_404(self, app, client):
        _login_super(client)
        r = client.get(self.GET.format(id=999999))
        assert r.status_code == 404


# ════════════════════════════════════════════════════════════════════════
# (4) The data-nodes page renders the config button + modal
# ════════════════════════════════════════════════════════════════════════
class TestDataNodesPageModal:

    def test_page_has_conn_config_button_and_modal(self, app, client):
        _login_super(client)
        _make_node(name="chr-cc-page")
        html = client.get("/admin/fleet/data-nodes").get_data(as_text=True)
        assert "data-dn-conn-config" in html, "«إعدادات الاتصال» button missing"
        assert 'id="dn-cc-modal"' in html, "conn-config modal missing"
        assert 'data-dn-cc-save' in html
        for field in ("pool_ranges", "dns", "gw_local_addr", "encryption",
                      "sstp_port", "sstp_cert_mode", "sstp_cert_name", "sstp_cert_cn"):
            assert f'data-cc="{field}"' in html, f"modal field {field} missing"


# ════════════════════════════════════════════════════════════════════════
# (3) Binding overlay — rendered script reflects per-node config
# ════════════════════════════════════════════════════════════════════════
class TestBindingOverlay:

    def test_build_bindings_overlays_conn_config(self, app):
        with app.app_context():
            from app.services.node_conn_config import set_conn_config
            from fleet.registry.onboarding_service import OnboardingService
            n = _make_node()
            set_conn_config(n, {
                "pool_ranges": "10.70.0.10-10.70.0.200",
                "dns": "9.9.9.9",
                "gw_local_addr": "10.7.0.1",
                "encryption": "yes",
                "sstp_port": 8443,
                "sstp_cert_cn": "vpn.example.com",
            }, commit=True)
            # Minimal job linked to the node so _build_bindings runs.
            from fleet.registry.models_onboarding import OnboardingJob
            import json as _json
            job = OnboardingJob(status="script_generated", chr_id=n.id)
            job.form_input = {"name": n.name}
            job.wg_keypair_ref = _json.dumps({})
            db.session.add(job); db.session.commit()

            svc = OnboardingService(config={})
            b = svc._build_bindings(job)
            assert b["IP_POOL_RANGES"] == "10.70.0.10-10.70.0.200"
            assert b["DNS_PUSH"] == "9.9.9.9"
            assert b["GW_LOCAL_ADDR"] == "10.7.0.1"
            assert b["PPP_ENCRYPTION"] == "yes"
            assert int(b["SSTP_PORT"]) == 8443
            assert b["SSTP_CERT_CN"] == "vpn.example.com"
            # auto cert mode ⇒ SSTP_CERT_NAME empty (template auto-creates).
            assert b["SSTP_CERT_NAME"] == ""
