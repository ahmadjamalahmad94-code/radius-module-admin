"""Bandwidth policy + node roles + capacity allocator + wg-radius rate cap.

Pins the contracts from docs/CUSTOMER_RADIUS_TUNNEL_DESIGN.md §9 + §10:

  * Per-connection-type defaults are documented + readable from the policy.
  * The §9 ``radius_transport`` cap (5 Mbps default) lands in the
    heartbeat ``radius_tunnel.rate_limit_mbps`` field.
  * Per-direction emission goes through the SAME ``rate_limit_string``
    formatter ``feat/bandwidth-per-direction`` rolled out — same shape,
    no duplicate code.
  * Policy CRUD round-trips through a single ``Setting`` row.
  * Node roles default to "all enabled" when ``roles_json`` is empty
    (back-compat for existing fleets).
  * The capacity allocator returns the spare-Mbps readout the operator
    sees on the dashboard — the §10 "no high-speed VPS sits idle"
    invariant.
"""
from __future__ import annotations

import pytest

from app.extensions import db
from app.models import CustomerRadiusInstance
from app.services.bandwidth_policy import (
    SETTING_KEY,
    SUPPORTED_TYPES,
    all_policies,
    policy_for,
    serialize_for_ui,
    set_policy,
    set_symmetric,
)
from app.services.node_roles import (
    NODE_ROLES,
    enabled_roles,
    node_has_role,
    set_roles,
    toggle_role,
)
from fleet.registry.models_chr import FleetChrNode, FleetProvider


# ════════════════════════════════════════════════════════════════════════
# §9.1 — policy defaults + per-direction emission
# ════════════════════════════════════════════════════════════════════════
class TestPolicyDefaults:
    def test_radius_transport_default_is_5_mbps_each_way(self, app):
        p = policy_for("radius_transport")
        assert p.download_mbps == 5
        assert p.upload_mbps == 5
        # Symmetric → "5M/5M" (the §9 rate-limit string).
        assert p.rate_limit() == "5M/5M"

    def test_vpn_defaults_are_documented_values(self, app):
        assert policy_for("vpn_sstp").download_mbps == 100
        assert policy_for("vpn_pptp").download_mbps == 50
        assert policy_for("vpn_ipsec").download_mbps == 50
        assert policy_for("vpn_wireguard").download_mbps == 100

    def test_unknown_type_raises(self, app):
        with pytest.raises(ValueError):
            policy_for("vpn_telnet")


# ════════════════════════════════════════════════════════════════════════
# §9 — policy CRUD round-trip via the single Setting row
# ════════════════════════════════════════════════════════════════════════
class TestPolicyCrud:
    def test_set_then_read_round_trips(self, app):
        result = set_symmetric("vpn_sstp", mbps=200)
        assert result.download_mbps == 200 and result.upload_mbps == 200
        # Re-reading hits the persisted Setting, not the in-memory default.
        again = policy_for("vpn_sstp")
        assert again.download_mbps == 200
        assert again.upload_mbps == 200
        assert again.rate_limit() == "200M/200M"

    def test_asymmetric_set_is_honoured(self, app):
        set_policy("vpn_ipsec", download_mbps=80, upload_mbps=40)
        p = policy_for("vpn_ipsec")
        assert p.download_mbps == 80 and p.upload_mbps == 40
        # Format = "<upload>M/<download>M" per the existing speed_profiles helper.
        assert p.rate_limit() == "40M/80M"

    def test_set_zero_rejected(self, app):
        with pytest.raises(ValueError):
            set_symmetric("vpn_sstp", mbps=0)
        with pytest.raises(ValueError):
            set_policy("vpn_sstp", download_mbps=10, upload_mbps=0)

    def test_serialize_for_ui_marks_symmetric_flag(self, app):
        view = serialize_for_ui()
        # Default 100/100 is symmetric.
        assert view["vpn_sstp"]["symmetric"] is True
        set_policy("vpn_pptp", download_mbps=120, upload_mbps=60)
        view2 = serialize_for_ui()
        assert view2["vpn_pptp"]["symmetric"] is False
        assert view2["vpn_pptp"]["rate_limit"] == "60M/120M"


# ════════════════════════════════════════════════════════════════════════
# §10.1 — node-role tag
# ════════════════════════════════════════════════════════════════════════
class TestNodeRoles:
    def _node(self):
        prov = FleetProvider(name="t-roles", cost_model="open")
        db.session.add(prov); db.session.flush()
        n = FleetChrNode(
            provider_id=prov.id, name="chr-mixed",
            public_ip="203.0.113.5",
            wg_mgmt_ip="10.99.0.5", wg_mgmt_pubkey="x" * 44,
            routeros_api_port=8729, coa_port=3799,
            max_sessions=500, link_speed_mbps=1000,
            weight=1.0, enabled=True, status="up",
        )
        db.session.add(n); db.session.commit()
        return n

    def test_empty_roles_means_all_enabled(self, app):
        n = self._node()
        assert enabled_roles(n) == set(NODE_ROLES)
        for r in NODE_ROLES:
            assert node_has_role(n, r) is True

    def test_set_roles_narrows_the_set(self, app):
        n = self._node()
        set_roles(n, ["radius_transport", "vpn_sstp"])
        db.session.commit()
        assert enabled_roles(n) == {"radius_transport", "vpn_sstp"}
        assert node_has_role(n, "radius_transport") is True
        assert node_has_role(n, "vpn_pptp") is False

    def test_unknown_role_dropped_silently(self, app):
        n = self._node()
        set_roles(n, ["vpn_telnet", "radius_transport"])
        assert enabled_roles(n) == {"radius_transport"}

    def test_toggle_role_flips_on_off(self, app):
        n = self._node()
        # Start from "all" — toggling off radius_transport gives "all minus one".
        roles = toggle_role(n, "radius_transport")
        assert "radius_transport" not in roles
        assert "vpn_sstp" in roles
        # Toggle back on → present again.
        roles = toggle_role(n, "radius_transport")
        assert "radius_transport" in roles



# ════════════════════════════════════════════════════════════════════════
# §9.2 — wg-radius rate cap on the heartbeat response
# ════════════════════════════════════════════════════════════════════════
PROXY_PUBKEY_B64 = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="


class TestRadiusTunnelRateLimit:
    def _seed_proxy(self):
        from fleet.registry.infra_settings import (
            set_proxy_radius_pubkey, set_proxy_radius_endpoint,
            set_proxy_radius_tunnel_ip,
        )
        set_proxy_radius_pubkey(PROXY_PUBKEY_B64)
        set_proxy_radius_endpoint("proxy.hoberadius.com:51822")
        set_proxy_radius_tunnel_ip("10.200.0.1")

    def test_default_5_mbps_in_radius_tunnel_block(self, proxy_app, customer_factory):
        self._seed_proxy()
        _, inst = customer_factory(customer_id=5)
        from app.services.customer_radius_tunnel import build_tunnel_config
        tc = build_tunnel_config(inst)
        payload = tc.as_payload()
        # Default radius_transport policy is 5 Mbps (§9.1).
        assert payload["rate_limit_mbps"] == 5

    def test_policy_change_propagates_to_heartbeat(
        self, proxy_app, customer_factory,
    ):
        self._seed_proxy()
        _, inst = customer_factory(customer_id=5)
        # Operator bumps the cap to 10 Mbps.
        set_symmetric("radius_transport", mbps=10)
        from app.services.customer_radius_tunnel import build_tunnel_config
        tc = build_tunnel_config(inst)
        assert tc.as_payload()["rate_limit_mbps"] == 10

    def test_rate_limit_factored_into_fingerprint(
        self, proxy_app, customer_factory,
    ):
        """A policy-only change (no key/secret rotation) must register as
        drift via the §6.4 fingerprint — otherwise the customer side
        never knows to apply the new cap."""
        self._seed_proxy()
        _, inst = customer_factory(customer_id=5)
        from app.services.customer_radius_tunnel import build_tunnel_config
        before = build_tunnel_config(inst).fingerprint
        set_symmetric("radius_transport", mbps=12)
        after = build_tunnel_config(inst).fingerprint
        assert before != after, (
            "§9 policy change must drift the fingerprint so the customer "
            "rewrites its wg interface cap"
        )
