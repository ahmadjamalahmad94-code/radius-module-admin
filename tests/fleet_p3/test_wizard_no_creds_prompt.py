"""fix/wizard-drop-initial-creds-prompt — the add-CHR wizard must NOT
ask the operator for an initial RouterOS username/password.

Background (see commit body): the auto-scoped-user feature in
feat/chr-auto-scoped-mgmt-user (merged at b7c2ac9) already
provisions ``hobe-panel`` in the scoped ``hobe-fleet-mgmt`` group +
persists a Fernet-encrypted strong password to
``fleet_chr_nodes.routeros_api_password_enc`` at ``generate_keys``.
The unified RouterOS script bakes the SAME pair into ``/user add``
on every node. The previously-rendered wizard step «معالج إضافة
CHR» asked for «مستخدم RouterOS الأولي» (placeholder ``admin`` —
a reserved-name trap) and «كلمة المرور الأولية»; both fields bound
only to dead JS state — ``WizardForm.from_dict`` never read them
and the push transport that would have consumed them isn't
registered in production. Removing them makes the wizard zero-entry
on credentials.

Invariants pinned here:

  (I)   The rendered wizard HTML must NOT carry the three
        ``bootstrap_*`` inputs (endpoint/user/pass) nor the
        «تُستخدم مرة واحدة فقط لتنزيل السكربت، ثم تُلغى» helper.
  (II)  An auto-provisioned card explains the zero-entry path.
  (III) Wizard POST to ``/admin/fleet/onboarding/jobs`` succeeds
        with NO bootstrap fields in the payload.
  (IV)  Node row carries the auto-minted creds + the rendered
        script's ``/user add`` line uses the SAME user + password
        (panel-mints-panel-knows is preserved end-to-end).
"""
from __future__ import annotations

import json
import re

import pytest

from app.extensions import db
from app.models import Admin
from fleet.health.routeros_creds import HARD_DEFAULT_USER, decrypt_password
from fleet.registry.models_chr import FleetChrNode, FleetProvider


def _login_admin(client):
    return client.post("/login", data={"username": "admin", "password": "admin12345"})


def _make_super_admin():
    adm = Admin.query.first()
    if adm and not adm.is_super_admin:
        adm.is_super_admin = True
        db.session.commit()


@pytest.fixture()
def provider_app(app):
    p = FleetProvider(name="contabo-de", cost_model="open", price_per_tb=0)
    db.session.add(p); db.session.commit()
    return app


# ════════════════════════════════════════════════════════════════════════
# (I) + (II) — rendered HTML
# ════════════════════════════════════════════════════════════════════════
class TestWizardHtmlNoCredsPrompt:

    def test_no_bootstrap_credentials_inputs(self, provider_app, client):
        _login_admin(client); _make_super_admin()
        resp = client.get("/admin/fleet/onboarding/new")
        assert resp.status_code == 200
        body = resp.get_data(as_text=True)
        # The three vestigial inputs MUST be gone.
        assert 'name="bootstrap_endpoint"' not in body
        assert 'name="bootstrap_user"' not in body
        assert 'name="bootstrap_pass"' not in body
        # Their Arabic labels are gone too.
        assert "مستخدم RouterOS الأولي" not in body
        assert "كلمة المرور الأولية" not in body
        # And the misleading helper that suggested the password was
        # «discarded» (which created the «panel never stores it →
        # can't poll» trap) is gone.
        assert "تُستخدم مرة واحدة فقط لتنزيل السكربت" not in body

    def test_auto_provision_callout_shown_instead(self, provider_app, client):
        _login_admin(client); _make_super_admin()
        body = client.get("/admin/fleet/onboarding/new").get_data(as_text=True)
        assert "اعتمادات الإدارة تلقائية" in body
        assert "hobe-panel" in body
        assert "hobe-fleet-mgmt" in body


# ════════════════════════════════════════════════════════════════════════
# (III) — wizard POST with NO bootstrap fields succeeds
# ════════════════════════════════════════════════════════════════════════
class TestWizardPostNoBootstrap:

    def test_create_draft_succeeds_without_any_bootstrap_fields(self, provider_app, client):
        _login_admin(client); _make_super_admin()
        # Payload mirrors what the updated wizard JS now sends — there
        # is NO `bootstrap` object at all.
        payload = {
            "provider": "contabo-de",
            "name": "chr-vpn-3",
            "public_ip": "1.1.1.3",
            "cost_model": "open",
            "max_sessions": 500,
            "link_speed_mbps": 1000,
            "weight": "1.0",
        }
        resp = client.post(
            "/admin/fleet/onboarding/jobs",
            data=json.dumps(payload),
            content_type="application/json",
        )
        assert resp.status_code in (200, 201), resp.get_data(as_text=True)
        body = resp.get_json()
        assert body["ok"] is True
        assert body["job"]["id"]

    def test_create_draft_succeeds_with_legacy_bootstrap_object_too(self, provider_app, client):
        """Defensive: a stale browser session still sending the legacy
        `bootstrap` object must not break the new server. The server-
        side parser ignored these keys before AND after the fix."""
        _login_admin(client); _make_super_admin()
        payload = {
            "provider": "contabo-de",
            "name": "chr-vpn-4",
            "public_ip": "1.1.1.4",
            "cost_model": "open",
            "max_sessions": 500,
            "link_speed_mbps": 1000,
            "bootstrap": {"endpoint": "1.2.3.4:8728", "user": "admin", "pass": "stale"},
        }
        resp = client.post(
            "/admin/fleet/onboarding/jobs",
            data=json.dumps(payload),
            content_type="application/json",
        )
        assert resp.status_code in (200, 201)


# ════════════════════════════════════════════════════════════════════════
# (IV) — script ↔ row match preserved (the headline invariant)
# ════════════════════════════════════════════════════════════════════════
class TestScriptRowMatchAfterWizardPost:

    def test_node_row_auto_mints_and_script_matches(self, provider_app, client):
        """End-to-end: wizard POST with NO creds → node row has
        auto-minted hobe-panel + Fernet-encrypted password →
        rendered script's /user add line uses the EXACT same user +
        password (panel-mints-panel-knows)."""
        _login_admin(client); _make_super_admin()

        # Seed the panel-infrastructure constants so render_script
        # doesn't trip the bindings check.
        from fleet.registry.infra_settings import (
            set_panel_pubkey, set_panel_endpoint, set_proxy_pubkey,
            set_proxy_endpoint, set_chr_shared_secret,
        )
        set_panel_pubkey("P" * 43 + "=")
        set_panel_endpoint("panel.example.com:51820")
        set_proxy_pubkey("Q" * 43 + "=")
        set_proxy_endpoint("proxy.example.com:51821")
        set_chr_shared_secret("central-secret-from-panel-xxxxxxxx")
        db.session.commit()

        # Wizard creates the draft with no bootstrap fields.
        resp = client.post(
            "/admin/fleet/onboarding/jobs",
            data=json.dumps({
                "provider": "contabo-de",
                "name": "chr-vpn-3",
                "public_ip": "1.1.1.3",
                "cost_model": "open",
                "max_sessions": 500,
                "link_speed_mbps": 1000,
            }),
            content_type="application/json",
        )
        assert resp.status_code in (200, 201)
        job_id = resp.get_json()["job"]["id"]

        # Advance through generate_keys + render_script (the same path
        # the «متابعة» button on the pending card triggers).
        resp = client.post(f"/admin/fleet/onboarding/jobs/{job_id}/advance")
        assert resp.status_code == 200, resp.get_data(as_text=True)
        adv_body = resp.get_json()
        assert adv_body["status"] == "script_generated"

        # Pull the rendered script + the node row.
        resp = client.get(f"/admin/fleet/onboarding/jobs/{job_id}/script")
        assert resp.status_code == 200
        script = resp.get_json()["script"]
        node_id = adv_body["chr_id"]
        node = db.session.get(FleetChrNode, node_id)

        # === panel-mints-panel-knows: row has auto-minted creds.
        assert node.routeros_api_user == HARD_DEFAULT_USER
        row_password = decrypt_password(node.routeros_api_password_enc)
        assert row_password and len(row_password) >= 24

        # === script's /user add line uses the EXACT same user/password
        # bound to the scoped management group.
        flat = re.sub(r' \\\n\s*', ' ', script)
        m = re.search(
            r'/user add name="([^"]+)"\s+group="([^"]+)"\s+password="([^"]+)"\s+comment="hobe-fleet-api-managed"',
            flat,
        )
        assert m, "scoped /user add line missing from rendered script"
        script_user, script_group, script_password = m.group(1), m.group(2), m.group(3)
        assert script_user == HARD_DEFAULT_USER == node.routeros_api_user
        assert script_group == "hobe-fleet-mgmt"
        assert script_password == row_password, (
            "script-baked password must equal node-row stored password "
            "(panel-mints-panel-knows invariant)"
        )
