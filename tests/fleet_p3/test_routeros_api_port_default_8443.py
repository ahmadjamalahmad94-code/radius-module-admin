"""fix/script-service-get-guard-foreach — routeros_api_port default is 8443.

Field incident: the CHR's auth log carried a recurring «login failure
for user hobe-panel via api». The panel only speaks REST over HTTPS
(``RouterOSClient`` builds ``https://<host>:<port>/rest/...`` exclusively)
— there is no binary RouterOS API client anywhere in the codebase. The
recurring failure was caused by an old POST /fleet/chr-nodes default of
8729 (the binary api-ssl port) in ``routes_chr.py:_validate_post``:
rows created with that default kept dialing port 8729 forever, hitting
the binary-api service with HTTPS traffic.

This test pins:
  1. NEW rows created without explicit ``routeros_api_port`` get 8443
     (REST) — not 8729 (binary).
  2. EXISTING rows with the stale 8729 default are healed at boot to
     8443 via the schema-heal step in ``app/__init__.py``.
  3. Explicit operator overrides (anything that isn't 8729) survive
     the boot-time heal untouched.
"""
from __future__ import annotations

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
    p = FleetProvider(
        name="port-prov", cost_model="open", price_per_tb=0,
        overage_allowed=False, billing_cycle_day=1,
    )
    db.session.add(p); db.session.commit()
    return p


_SEQ = [40]


def _make_node(**kw) -> FleetChrNode:
    _SEQ[0] += 1
    base = dict(
        provider_id=_provider().id,
        name=f"chr-port-{_SEQ[0]}",
        public_ip=f"203.0.113.{_SEQ[0]}",
        wg_mgmt_ip=f"10.99.0.{_SEQ[0]}", wg_mgmt_pubkey="x" * 44,
        max_sessions=500, link_speed_mbps=1000, weight=1.0,
        enabled=True, drain=False, status="up",
        cpu_pct=0, active_sessions=0,
    )
    base.update(kw)
    n = FleetChrNode(**base)
    db.session.add(n); db.session.commit()
    return n


# ════════════════════════════════════════════════════════════════════════
# (1) routes_chr.py _validate_post default is 8443, not 8729
# ════════════════════════════════════════════════════════════════════════
class TestCreateDefault:

    def test_payload_without_port_gets_8443(self, app):
        """The CREATE path's fallback when routeros_api_port is
        omitted from the POST body must be 8443 (REST), NOT 8729
        (binary api-ssl). The fallback was changed because rows
        with port=8729 produce recurring CHR auth log noise."""
        from fleet.registry.routes_chr import _validate_create_payload as _validate_post
        payload = {
            "provider_id": _provider().id,
            "name": "chr-create-no-port",
            "public_ip": "203.0.113.99",
            "wg_mgmt_ip": "10.99.0.99",
            "wg_mgmt_pubkey": "y" * 44,
            "max_sessions": 500,
            "link_speed_mbps": 1000,
        }
        spec, err = _validate_post(payload)
        assert err is None, err
        assert spec["routeros_api_port"] == 8443, (
            "default routeros_api_port must be 8443 (REST/www-ssl); "
            "the old 8729 default caused recurring «login failure for "
            "user hobe-panel via api» log noise because the metrics "
            "collector dialed HTTPS against a binary-api port"
        )

    def test_explicit_override_survives(self, app):
        """Operator-provided port is preserved verbatim — only the
        empty/missing fallback is healed."""
        from fleet.registry.routes_chr import _validate_create_payload as _validate_post
        payload = {
            "provider_id": _provider().id,
            "name": "chr-explicit-port",
            "public_ip": "203.0.113.101",
            "wg_mgmt_ip": "10.99.0.101",
            "wg_mgmt_pubkey": "z" * 44,
            "max_sessions": 500,
            "link_speed_mbps": 1000,
            "routeros_api_port": 9443,
        }
        spec, err = _validate_post(payload)
        assert err is None, err
        assert spec["routeros_api_port"] == 9443


# ════════════════════════════════════════════════════════════════════════
# (2) Boot-time heal moves stale 8729 rows to 8443
# ════════════════════════════════════════════════════════════════════════
class TestBootHeal:

    def test_existing_row_with_8729_is_healed_on_init(self, app):
        """Simulate a row that was created by the OLD code (with the
        wrong 8729 default), then re-run the init schema heal — the
        row must end at 8443."""
        with app.app_context():
            n = _make_node(name="chr-stale-8729", routeros_api_port=8729)
            n_id = n.id
            # Re-run init_database which contains the heal.
            from app import init_database
            init_database(app)
            healed = db.session.get(FleetChrNode, n_id)
            assert healed.routeros_api_port == 8443, (
                "boot-time heal failed to update routeros_api_port=8729 "
                "(binary api-ssl) to 8443 (REST/www-ssl)"
            )

    def test_explicit_non_8729_value_survives_heal(self, app):
        """Operator-set port that isn't the bad default is left alone."""
        with app.app_context():
            n = _make_node(name="chr-explicit-survives",
                           routeros_api_port=9443)
            n_id = n.id
            from app import init_database
            init_database(app)
            survived = db.session.get(FleetChrNode, n_id)
            assert survived.routeros_api_port == 9443, (
                "boot-time heal must only touch routeros_api_port=8729 "
                "rows; an operator override of 9443 was clobbered"
            )


# ════════════════════════════════════════════════════════════════════════
# (3) Eager-warm of onboarding lazy imports
# ════════════════════════════════════════════════════════════════════════
class TestLazyImportWarmUp:

    def test_warm_function_imports_every_sibling(self, app):
        """The .rsc download 503 owner saw was a multi-worker cold-start
        race on importlib lazy resolution. ``_warm_onboarding_lazy_imports``
        eager-imports every sibling at boot so no worker can 503 on
        first request. Verify each module is resident in sys.modules
        AFTER create_app runs."""
        import sys
        for sibling in (
            "fleet.registry.wg_keys",
            "fleet.registry.secrets_vault",
            "fleet.registry.script_render",
            "fleet.registry.bootstrap_push",
            "fleet.registry.script_bindings_check",
        ):
            assert sibling in sys.modules, (
                f"{sibling} not warmed at boot — the .rsc download route "
                f"can 503 on a worker that hasn't yet imported it"
            )
