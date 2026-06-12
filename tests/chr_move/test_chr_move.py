"""feat/panel-chr-move-public-ip — service-layer tests for the CHR move.

Pins the contract from ``docs/CHR_MOVE_DESIGN.md`` §7:

  * Eligibility refusals carry precise Arabic messages.
  * The routing update writes ``[target.id]`` into every realm route
    owned by the customer's instance.
  * The CoA emitter is called with the right realm + reason +
    target_node_id; the signature header is built from the same
    HMAC scheme the inbound ``/api/proxy/*`` verifier uses.
  * Old → new public IP surface in the result struct.
  * Idempotency: re-running with the same target = no-op success.
  * CoA failure does NOT roll back the routing change.
"""
from __future__ import annotations

import json

import pytest

from app.extensions import db
from app.models import (
    Customer,
    CustomerRadiusInstance,
    ProxyRealmRoute,
)
from app.services.chr_move import (
    ChrMoveError,
    MoveResult,
    current_public_ips_for_customer,
    eligible_targets,
    move_customer_to_chr,
)
from app.services.coa_disconnect import (
    CoaResult,
    STATUS_FAILED,
    STATUS_NO_ENDPOINT,
    STATUS_NO_SECRET,
    STATUS_OK,
    STATUS_PENDING_PROXY_ENDPOINT,
)
from fleet.registry.models_chr import FleetChrNode, FleetProvider


# ════════════════════════════════════════════════════════════════════════
# Fixtures
# ════════════════════════════════════════════════════════════════════════
@pytest.fixture()
def make_node(app):
    """Persist a FleetChrNode with sensible defaults — every test override
    can pass kwargs to shape eligibility cases."""
    seq = [0]
    provider_cache: dict = {}

    def _provider():
        if "p" not in provider_cache:
            p = FleetProvider(name="chrmove-tests", cost_model="open")
            db.session.add(p); db.session.flush()
            provider_cache["p"] = p
        return provider_cache["p"]

    def _make(**overrides):
        seq[0] += 1
        defaults = dict(
            provider_id=_provider().id,
            name=f"chr-test-{seq[0]}",
            public_ip=f"203.0.113.{seq[0]}",
            wg_mgmt_ip=f"10.99.0.{seq[0] + 10}",
            wg_mgmt_pubkey="x" * 44,
            routeros_api_port=8729,
            coa_port=3799,
            max_sessions=500,
            link_speed_mbps=1000,
            enabled=True,
            drain=False,
            status="up",
            roles_json=json.dumps(["radius_transport", "vpn_sstp", "vpn_pptp", "vpn_ipsec", "vpn_wireguard"]),
        )
        defaults.update(overrides)
        node = FleetChrNode(**defaults)
        db.session.add(node)
        db.session.commit()
        return node

    return _make


@pytest.fixture()
def make_customer(app):
    """Customer + CustomerRadiusInstance + one ProxyRealmRoute. Mirrors the
    real schema relationship every move call walks."""
    seq = [0]

    def _make(allowed_node_ids: list[int] | None = None):
        seq[0] += 1
        cust = Customer(
            company_name=f"Test Cust {seq[0]}",
            email=f"cust{seq[0]}@example.com",
            phone="",
        )
        db.session.add(cust)
        db.session.flush()

        inst = CustomerRadiusInstance(
            customer_id=cust.id,
            instance_name=f"client{cust.id}-radius",
            realm=f"client{cust.id}",
            radius_auth_ip=f"10.200.{cust.id}.2",
            radius_auth_port=1812,
            radius_acct_port=1813,
            status="online",
        )
        db.session.add(inst)
        db.session.flush()

        route = ProxyRealmRoute(
            realm=inst.realm,
            customer_id=cust.id,
            radius_instance_id=inst.id,
            target_radius_ip=inst.radius_auth_ip,
            target_auth_port=1812,
            target_acct_port=1813,
            status="active",
        )
        route.allowed_fleet_chr_node_ids = list(allowed_node_ids or [])
        db.session.add(route)
        db.session.commit()
        return cust, inst, route

    return _make


@pytest.fixture()
def mock_coa():
    """A test-double emitter that records every call + lets the test
    return any ``CoaResult``. Pass it as ``coa_emitter=mock_coa.factory``."""

    class _Recorder:
        def __init__(self):
            self.calls: list[dict] = []
            self.return_value = CoaResult(status=STATUS_OK, http_status=200,
                                          message="ok", request_id="req-1")

        def factory(self, **kwargs):
            self.calls.append(kwargs)
            return self.return_value

    return _Recorder()


# ════════════════════════════════════════════════════════════════════════
# Eligibility refusals
# ════════════════════════════════════════════════════════════════════════
class TestRefusals:

    def test_move_refuses_when_no_radius_instance(self, app, make_node):
        cust = Customer(company_name="no inst", email="x@example.com", phone="")
        db.session.add(cust); db.session.commit()
        target = make_node()
        with pytest.raises(ChrMoveError, match="realm RADIUS"):
            move_customer_to_chr(cust, target)

    def test_move_refuses_disabled_target(self, app, make_customer, make_node):
        cust, _, _ = make_customer()
        target = make_node(enabled=False)
        with pytest.raises(ChrMoveError, match="معطَّلة"):
            move_customer_to_chr(cust, target)

    def test_move_refuses_drain_target(self, app, make_customer, make_node):
        cust, _, _ = make_customer()
        target = make_node(drain=True)
        with pytest.raises(ChrMoveError, match="التصريف"):
            move_customer_to_chr(cust, target)

    def test_move_refuses_status_disabled(self, app, make_customer, make_node):
        cust, _, _ = make_customer()
        target = make_node(status="disabled")
        with pytest.raises(ChrMoveError, match="disabled"):
            move_customer_to_chr(cust, target)

    def test_move_refuses_down_target(self, app, make_customer, make_node):
        cust, _, _ = make_customer()
        target = make_node(status="down")
        with pytest.raises(ChrMoveError, match="غير قابلة للوصول"):
            move_customer_to_chr(cust, target)

    def test_move_refuses_no_vpn_role(self, app, make_customer, make_node):
        """A pure radius_transport node can't terminate user VPN."""
        cust, _, _ = make_customer()
        target = make_node(roles_json=json.dumps(["radius_transport"]))
        with pytest.raises(ChrMoveError, match="VPN"):
            move_customer_to_chr(cust, target)

    def test_move_refuses_nonexistent_target(self, app, make_customer):
        cust, _, _ = make_customer()
        with pytest.raises(ChrMoveError, match="غير موجودة"):
            move_customer_to_chr(cust, None)


# ════════════════════════════════════════════════════════════════════════
# Eligible targets list — same filter as available_nodes + has VPN role
# ════════════════════════════════════════════════════════════════════════
class TestEligibleTargets:

    def test_returns_only_eligible_nodes(self, app, make_node):
        # Good ones + bad ones.
        ok1 = make_node(name="chr-ok-1", public_ip="1.1.1.1")
        ok2 = make_node(name="chr-ok-2", public_ip="1.1.1.2",
                        roles_json=json.dumps(["vpn_sstp"]))
        make_node(enabled=False, public_ip="2.2.2.1")
        make_node(drain=True, public_ip="2.2.2.2")
        make_node(status="disabled", public_ip="2.2.2.3")
        make_node(roles_json=json.dumps(["radius_transport"]), public_ip="2.2.2.4")

        ids = {n.id for n in eligible_targets()}
        assert ok1.id in ids and ok2.id in ids
        assert len(ids) == 2


# ════════════════════════════════════════════════════════════════════════
# Routing update
# ════════════════════════════════════════════════════════════════════════
class TestRoutingUpdate:

    def test_writes_target_id_into_every_route(self, app, make_customer, make_node, mock_coa):
        node_a = make_node(name="chr-A", public_ip="9.9.9.1")
        node_b = make_node(name="chr-B", public_ip="9.9.9.2")
        cust, inst, route = make_customer(allowed_node_ids=[node_a.id])
        assert route.allowed_fleet_chr_node_ids == [node_a.id]

        result = move_customer_to_chr(cust, node_b, coa_emitter=mock_coa.factory)

        db.session.refresh(route)
        assert route.allowed_fleet_chr_node_ids == [node_b.id]
        assert result.routing_changed is True

    def test_resets_drift_counters_so_proxy_refetches(self, app, make_customer, make_node, mock_coa):
        node_a = make_node(public_ip="9.9.9.1")
        node_b = make_node(public_ip="9.9.9.2")
        cust, inst, _ = make_customer(allowed_node_ids=[node_a.id])
        inst.last_reported_fingerprint = "stale-fingerprint"
        inst.drift_cycles = 2
        db.session.commit()

        move_customer_to_chr(cust, node_b, coa_emitter=mock_coa.factory)

        db.session.refresh(inst)
        assert inst.last_reported_fingerprint == ""
        assert inst.drift_cycles == 0


# ════════════════════════════════════════════════════════════════════════
# Old → new public IP surface
# ════════════════════════════════════════════════════════════════════════
class TestPublicIpSurface:

    def test_result_carries_old_and_new_ips(self, app, make_customer, make_node, mock_coa):
        node_a = make_node(name="chr-A", public_ip="9.9.9.10")
        node_b = make_node(name="chr-B", public_ip="9.9.9.20")
        cust, _, _ = make_customer(allowed_node_ids=[node_a.id])

        result = move_customer_to_chr(cust, node_b, coa_emitter=mock_coa.factory)

        assert result.old_public_ips == ("9.9.9.10",)
        assert result.target_public_ip == "9.9.9.20"
        assert result.target_node_name == "chr-B"
        assert result.realm == cust.radius_instance.realm

    def test_empty_old_ips_when_no_prior_assignment(self, app, make_customer, make_node, mock_coa):
        """First-time assign: old IPs is empty; new IP is the target."""
        target = make_node(public_ip="9.9.9.100")
        cust, _, _ = make_customer(allowed_node_ids=[])
        result = move_customer_to_chr(cust, target, coa_emitter=mock_coa.factory)
        assert result.old_public_ips == ()
        assert result.target_public_ip == "9.9.9.100"

    def test_current_public_ips_helper_reads_through_routes(self, app, make_customer, make_node):
        node_a = make_node(public_ip="1.1.1.10")
        node_b = make_node(public_ip="1.1.1.11")
        cust, _, route = make_customer(allowed_node_ids=[node_a.id, node_b.id])
        # Helper returns sorted unique IPs.
        ips = current_public_ips_for_customer(cust)
        assert ips == ["1.1.1.10", "1.1.1.11"]


# ════════════════════════════════════════════════════════════════════════
# CoA emission — signed payload + correct call args
# ════════════════════════════════════════════════════════════════════════
class TestCoaEmission:

    def test_coa_called_with_realm_reason_target(self, app, make_customer, make_node, mock_coa):
        node_a = make_node(public_ip="9.0.0.1")
        node_b = make_node(public_ip="9.0.0.2")
        cust, inst, _ = make_customer(allowed_node_ids=[node_a.id])

        move_customer_to_chr(cust, node_b, coa_emitter=mock_coa.factory)

        assert len(mock_coa.calls) == 1
        call = mock_coa.calls[0]
        assert call["realm"] == inst.realm
        assert call["target_node_id"] == node_b.id
        assert call["reason"] == "panel:chr-move"

    def test_coa_called_even_on_same_chr_noop(self, app, make_customer, make_node, mock_coa):
        """Same-target move = routing-no-op, but CoA still fires so the
        operator can force-reconnect on the same node from the same button."""
        node = make_node()
        cust, _, _ = make_customer(allowed_node_ids=[node.id])
        result = move_customer_to_chr(cust, node, coa_emitter=mock_coa.factory)
        assert result.routing_changed is False
        assert len(mock_coa.calls) == 1

    def test_result_carries_coa_outcome(self, app, make_customer, make_node, mock_coa):
        node = make_node()
        cust, _, _ = make_customer()
        mock_coa.return_value = CoaResult(
            status=STATUS_OK, http_status=200,
            message="تمّ", request_id="req-test-42",
        )
        result = move_customer_to_chr(cust, node, coa_emitter=mock_coa.factory)
        assert result.coa_status == STATUS_OK
        assert result.coa_http_status == 200
        assert result.coa_request_id == "req-test-42"


# ════════════════════════════════════════════════════════════════════════
# CoA failure does NOT roll back the routing change
# ════════════════════════════════════════════════════════════════════════
class TestDurabilityOnCoaFailure:

    def test_routing_persists_when_coa_returns_failed(self, app, make_customer, make_node, mock_coa):
        node_a = make_node(public_ip="9.0.0.5")
        node_b = make_node(public_ip="9.0.0.6")
        cust, _, route = make_customer(allowed_node_ids=[node_a.id])

        mock_coa.return_value = CoaResult(
            status=STATUS_FAILED, http_status=502,
            message="proxy 502", request_id="r1",
        )
        result = move_customer_to_chr(cust, node_b, coa_emitter=mock_coa.factory)

        db.session.refresh(route)
        # Routing changed even though CoA failed.
        assert route.allowed_fleet_chr_node_ids == [node_b.id]
        assert result.routing_changed is True
        assert result.coa_status == STATUS_FAILED

    def test_pending_proxy_endpoint_surfaces_distinctly(self, app, make_customer, make_node, mock_coa):
        """The proxy doesn't yet implement the CoA endpoint → status
        ``pending_proxy_endpoint`` (NOT failed) so the UI says «بانتظار»."""
        node = make_node()
        cust, _, _ = make_customer()
        mock_coa.return_value = CoaResult(
            status=STATUS_PENDING_PROXY_ENDPOINT, http_status=501,
            message="not yet", request_id="r2",
        )
        result = move_customer_to_chr(cust, node, coa_emitter=mock_coa.factory)
        assert result.coa_status == STATUS_PENDING_PROXY_ENDPOINT


# ════════════════════════════════════════════════════════════════════════
# Idempotency — same target re-run = no-op success
# ════════════════════════════════════════════════════════════════════════
class TestIdempotency:

    def test_second_run_to_same_target_is_noop(self, app, make_customer, make_node, mock_coa):
        node = make_node(public_ip="9.0.0.9")
        cust, _, route = make_customer(allowed_node_ids=[])
        # First call: routing change.
        r1 = move_customer_to_chr(cust, node, coa_emitter=mock_coa.factory)
        assert r1.routing_changed is True

        # Second call to same target: routing unchanged, but CoA still fires.
        r2 = move_customer_to_chr(cust, node, coa_emitter=mock_coa.factory)
        assert r2.routing_changed is False
        db.session.refresh(route)
        assert route.allowed_fleet_chr_node_ids == [node.id]
        assert len(mock_coa.calls) == 2  # both calls emit


# ════════════════════════════════════════════════════════════════════════
# Audit — actor + from/to + CoA outcome persisted
# ════════════════════════════════════════════════════════════════════════
class TestAudit:

    def test_audit_row_written(self, app, make_customer, make_node, mock_coa):
        """The audit row goes through ``app.auth.routes.audit`` which reads
        request-context fields (ip, ua). The production path is always
        inside a request; we simulate one here."""
        from app.models import AuditLog

        node_a = make_node(name="chr-OLD", public_ip="1.2.3.4")
        node_b = make_node(name="chr-NEW", public_ip="5.6.7.8")
        cust, _, _ = make_customer(allowed_node_ids=[node_a.id])

        with app.test_request_context("/admin/customers/x/move-chr", method="POST"):
            move_customer_to_chr(
                cust, node_b, actor="ops-tester", coa_emitter=mock_coa.factory,
            )

        rows = (
            AuditLog.query
            .filter_by(action="chr_move_executed",
                       entity_type="customer",
                       entity_id=str(cust.id))
            .all()
        )
        assert rows, "expected an audit row for chr_move_executed"
        meta = rows[-1].meta or {}
        assert meta.get("to_node_id") == node_b.id
        assert meta.get("to_public_ip") == "5.6.7.8"
        assert meta.get("from_public_ips") == ["1.2.3.4"]
        assert meta.get("coa_status") == STATUS_OK
        assert meta.get("actor") == "ops-tester"
        assert meta.get("routing_changed") is True


# ════════════════════════════════════════════════════════════════════════
# CoA emitter — signature + URL build + status mapping (no live HTTP)
# ════════════════════════════════════════════════════════════════════════
class TestCoaEmitterStandalone:
    """The chr_move tests above mock the emitter wholesale. These tests
    pin the emitter's own contract: it constructs the signed request the
    proxy will validate, and maps HTTP outcomes to the right status."""

    def test_emit_returns_no_secret_when_unset(self, app):
        from app.services.coa_disconnect import emit_coa_disconnect
        result = emit_coa_disconnect(
            realm="client1", target_node_id=1,
            proxy_base_url="https://proxy.test", shared_secret="",
        )
        assert result.status == STATUS_NO_SECRET

    def test_emit_returns_no_endpoint_when_unset(self, app):
        from app.services.coa_disconnect import emit_coa_disconnect
        result = emit_coa_disconnect(
            realm="client1", target_node_id=1,
            proxy_base_url="", shared_secret="some-secret",
        )
        assert result.status == STATUS_NO_ENDPOINT

    def test_emit_builds_signed_request(self, app, monkeypatch):
        """The emitter must:
          (a) POST to <base>/api/proxy/coa/disconnect,
          (b) carry an X-Proxy-Token: <ts>:<nonce>:<hmac> header,
          (c) JSON-body with realm, reason, target_node_id, request_id.
        """
        import hashlib
        import hmac as _hmac
        from app.services import coa_disconnect as cd

        captured: dict = {}

        def fake_post(url, payload, headers, *, timeout=5.0):
            captured["url"] = url
            captured["payload"] = payload
            captured["headers"] = headers
            return 200, '{"ok":true}'

        monkeypatch.setattr(cd, "_http_post_json", fake_post)

        secret = "test-shared-secret-xx"
        result = cd.emit_coa_disconnect(
            realm="client42",
            target_node_id=7,
            proxy_base_url="https://proxy.example.com:8443",
            shared_secret=secret,
        )
        assert result.status == STATUS_OK
        assert captured["url"] == "https://proxy.example.com:8443/api/proxy/coa/disconnect"
        assert captured["payload"]["realm"] == "client42"
        assert captured["payload"]["target_node_id"] == 7
        assert captured["payload"]["reason"] == "panel:chr-move"
        assert "panel_request_id" in captured["payload"]

        # Header shape <ts>:<nonce>:<hmac>; HMAC verifies against the secret.
        token = captured["headers"]["X-Proxy-Token"]
        ts, nonce, mac = token.split(":", 2)
        expected = _hmac.new(secret.encode(), f"{ts}:{nonce}".encode(),
                             hashlib.sha256).hexdigest()
        assert mac == expected

    def test_emit_maps_404_to_pending_proxy_endpoint(self, app, monkeypatch):
        from app.services import coa_disconnect as cd

        monkeypatch.setattr(
            cd, "_http_post_json",
            lambda url, payload, headers, *, timeout=5.0: (404, "not found"),
        )
        result = cd.emit_coa_disconnect(
            realm="x", target_node_id=1,
            proxy_base_url="https://p", shared_secret="s",
        )
        assert result.status == STATUS_PENDING_PROXY_ENDPOINT
        assert result.http_status == 404

    def test_emit_maps_5xx_to_failed(self, app, monkeypatch):
        from app.services import coa_disconnect as cd

        monkeypatch.setattr(
            cd, "_http_post_json",
            lambda url, payload, headers, *, timeout=5.0: (503, "down"),
        )
        result = cd.emit_coa_disconnect(
            realm="x", target_node_id=1,
            proxy_base_url="https://p", shared_secret="s",
        )
        assert result.status == STATUS_FAILED
        assert result.http_status == 503

    def test_emit_maps_network_error_to_failed(self, app, monkeypatch):
        import urllib.error
        from app.services import coa_disconnect as cd

        def boom(url, payload, headers, *, timeout=5.0):
            raise urllib.error.URLError("connection refused")

        monkeypatch.setattr(cd, "_http_post_json", boom)
        result = cd.emit_coa_disconnect(
            realm="x", target_node_id=1,
            proxy_base_url="https://p", shared_secret="s",
        )
        assert result.status == STATUS_FAILED
        assert result.http_status == 0
