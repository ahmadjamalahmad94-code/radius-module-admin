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
    STATUS_DONE,
    STATUS_FAILED,
    STATUS_PENDING,
    STATUS_SENT,
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
    """A test-double enqueuer that records every call + lets the test
    return any ``CoaResult``. Pass it as ``coa_emitter=mock_coa.factory``.

    Default behaviour: returns ``status=pending`` with a deterministic
    command_id — matches the production queue-enqueue path."""

    class _Recorder:
        def __init__(self):
            self.calls: list[dict] = []
            self.return_value = CoaResult(
                status=STATUS_PENDING,
                message="أُدرج الأمر في قائمة CoA — ≤60 ثانية",
                command_id="cmd-test-1",
            )

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
class TestCoaEnqueue:

    def test_coa_enqueued_with_realm_reason_target_customer(self, app, make_customer, make_node, mock_coa):
        node_a = make_node(public_ip="9.0.0.1")
        node_b = make_node(public_ip="9.0.0.2")
        cust, inst, _ = make_customer(allowed_node_ids=[node_a.id])

        move_customer_to_chr(cust, node_b, coa_emitter=mock_coa.factory)

        assert len(mock_coa.calls) == 1
        call = mock_coa.calls[0]
        assert call["realm"] == inst.realm
        assert call["target_node_id"] == node_b.id
        assert call["reason"] == "panel:chr-move"
        # The queue model also routes the customer_id through so the
        # later /api/proxy/coa-result can audit against the right row.
        assert call["customer_id"] == cust.id

    def test_coa_enqueued_even_on_same_chr_noop(self, app, make_customer, make_node, mock_coa):
        """Same-target move = routing-no-op, but the command still gets
        enqueued so the operator can force-reconnect on the same node
        from the same button (the «خلّيه يعيد الاتصال» case)."""
        node = make_node()
        cust, _, _ = make_customer(allowed_node_ids=[node.id])
        result = move_customer_to_chr(cust, node, coa_emitter=mock_coa.factory)
        assert result.routing_changed is False
        assert len(mock_coa.calls) == 1

    def test_result_carries_enqueue_outcome(self, app, make_customer, make_node, mock_coa):
        """In the QUEUE model the result carries the pending status +
        the command_id the proxy will echo back via coa-result."""
        node = make_node()
        cust, _, _ = make_customer()
        mock_coa.return_value = CoaResult(
            status=STATUS_PENDING,
            message="أُدرج",
            command_id="cmd-test-42",
        )
        result = move_customer_to_chr(cust, node, coa_emitter=mock_coa.factory)
        assert result.coa_status == STATUS_PENDING
        assert result.coa_request_id == "cmd-test-42"


class TestQueueIntegration:
    """End-to-end against the real ``enqueue_coa_disconnect`` (no mock)
    — proves the move service writes an actual PendingCoaCommand row
    the routing-table endpoint will publish."""

    def test_real_enqueue_creates_pending_row(self, app, make_customer, make_node):
        from app.models import PendingCoaCommand
        node = make_node(public_ip="9.9.9.99")
        cust, inst, _ = make_customer()

        result = move_customer_to_chr(cust, node)

        rows = (
            PendingCoaCommand.query
            .filter_by(realm=inst.realm)
            .all()
        )
        assert len(rows) == 1
        row = rows[0]
        assert row.command_id == result.coa_request_id
        assert row.status == STATUS_PENDING
        assert row.target_node_id == node.id
        assert row.reason == "panel:chr-move"
        assert row.customer_id == cust.id


# ════════════════════════════════════════════════════════════════════════
# CoA failure does NOT roll back the routing change
# ════════════════════════════════════════════════════════════════════════
class TestDurabilityOnEnqueueFailure:

    def test_routing_persists_when_enqueue_raises(self, app, make_customer, make_node):
        """In the queue model the enqueue is a normal DB write — if it
        somehow raises (disk full, etc.), the routing change is already
        committed and stays durable. We simulate by injecting a raising
        emitter and asserting the route is still rewritten."""
        node_a = make_node(public_ip="9.0.0.5")
        node_b = make_node(public_ip="9.0.0.6")
        cust, _, route = make_customer(allowed_node_ids=[node_a.id])

        def boom(**kwargs):
            raise RuntimeError("disk full")

        with pytest.raises(RuntimeError):
            move_customer_to_chr(cust, node_b, coa_emitter=boom)

        # Routing change persisted even though the enqueuer raised.
        db.session.refresh(route)
        assert route.allowed_fleet_chr_node_ids == [node_b.id]


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
        assert meta.get("coa_status") == STATUS_PENDING
        assert meta.get("actor") == "ops-tester"
        assert meta.get("routing_changed") is True


# ════════════════════════════════════════════════════════════════════════
# Queue helpers — enqueue + alive_commands + serialize + apply_coa_result
# ════════════════════════════════════════════════════════════════════════
class TestCoaQueue:
    """Direct tests on the queue layer — independent of chr_move so the
    queue contract can be verified without the routing-update path."""

    def test_enqueue_creates_pending_row(self, app):
        from app.models import PendingCoaCommand
        from app.services.coa_disconnect import enqueue_coa_disconnect

        result = enqueue_coa_disconnect(
            realm="client9", target_node_id=99, customer_id=1,
        )
        row = PendingCoaCommand.query.filter_by(command_id=result.command_id).one()
        assert row.status == STATUS_PENDING
        assert row.realm == "client9"
        assert row.target_node_id == 99
        assert row.customer_id == 1
        assert row.coa_code is None
        assert row.completed_at is None

    def test_alive_commands_excludes_terminal(self, app):
        from app.services.coa_disconnect import (
            alive_commands, apply_coa_result, enqueue_coa_disconnect,
        )
        c1 = enqueue_coa_disconnect(realm="r1", target_node_id=1)
        c2 = enqueue_coa_disconnect(realm="r2", target_node_id=2)
        apply_coa_result(command_id=c1.command_id, status="done", coa_code=41)

        alive_ids = {r.command_id for r in alive_commands()}
        assert c1.command_id not in alive_ids
        assert c2.command_id in alive_ids

    def test_serialize_for_routing_table_marks_sent(self, app):
        from app.models import PendingCoaCommand
        from app.services.coa_disconnect import (
            alive_commands, enqueue_coa_disconnect, serialize_for_routing_table,
        )
        c = enqueue_coa_disconnect(realm="r3", target_node_id=3)
        serialized = serialize_for_routing_table(alive_commands(), mark_sent=True)
        assert any(s["id"] == c.command_id for s in serialized)

        row = PendingCoaCommand.query.filter_by(command_id=c.command_id).one()
        assert row.status == STATUS_SENT
        assert row.picked_up_at is not None

        # Second publish: still alive, still serialized — sent is not
        # terminal, the proxy may need to retry over multiple polls.
        again = serialize_for_routing_table(alive_commands(), mark_sent=True)
        assert any(s["id"] == c.command_id for s in again)

    def test_serialize_payload_shape(self, app):
        """Exact contract the proxy parses — every key + the publish
        envelope ordering."""
        from app.services.coa_disconnect import (
            alive_commands, enqueue_coa_disconnect, serialize_for_routing_table,
        )
        c = enqueue_coa_disconnect(
            realm="client42", target_node_id=7, reason="panel:chr-move",
        )
        row = serialize_for_routing_table(alive_commands(), mark_sent=False)[0]
        assert set(row.keys()) == {"id", "realm", "action", "target_node_id", "reason"}
        assert row["id"] == c.command_id
        assert row["realm"] == "client42"
        assert row["action"] == "disconnect"
        assert row["target_node_id"] == 7
        assert row["reason"] == "panel:chr-move"

    def test_apply_coa_result_marks_done(self, app):
        from app.models import PendingCoaCommand
        from app.services.coa_disconnect import (
            apply_coa_result, enqueue_coa_disconnect,
        )
        c = enqueue_coa_disconnect(realm="r4", target_node_id=4)

        with app.test_request_context("/api/proxy/coa-result", method="POST"):
            outcome = apply_coa_result(
                command_id=c.command_id, status="done",
                detail="ACK received", coa_code=41,
            )
        assert outcome.found is True
        assert outcome.already_terminal is False
        assert outcome.new_status == STATUS_DONE

        row = PendingCoaCommand.query.filter_by(command_id=c.command_id).one()
        assert row.status == STATUS_DONE
        assert row.coa_code == 41
        assert "ACK received" in row.detail
        assert row.completed_at is not None

    def test_apply_coa_result_marks_failed_with_nak_code(self, app):
        from app.models import PendingCoaCommand
        from app.services.coa_disconnect import (
            apply_coa_result, enqueue_coa_disconnect,
        )
        c = enqueue_coa_disconnect(realm="r5", target_node_id=5)
        with app.test_request_context("/api/proxy/coa-result", method="POST"):
            apply_coa_result(
                command_id=c.command_id, status="failed",
                detail="NAS unreachable", coa_code=42,
            )
        row = PendingCoaCommand.query.filter_by(command_id=c.command_id).one()
        assert row.status == STATUS_FAILED
        assert row.coa_code == 42

    def test_apply_coa_result_is_idempotent_on_terminal(self, app):
        """The proxy may re-post the same result on retry. Re-applying a
        terminal state must NOT toggle it and must NOT raise."""
        from app.models import PendingCoaCommand
        from app.services.coa_disconnect import (
            apply_coa_result, enqueue_coa_disconnect,
        )
        c = enqueue_coa_disconnect(realm="r6", target_node_id=6)
        with app.test_request_context("/api/proxy/coa-result", method="POST"):
            apply_coa_result(command_id=c.command_id, status="done", coa_code=41)
            r2 = apply_coa_result(
                command_id=c.command_id, status="failed",
                detail="trying to flip", coa_code=42,
            )
        assert r2.found is True
        assert r2.already_terminal is True
        # Status preserved as the first terminal write.
        row = PendingCoaCommand.query.filter_by(command_id=c.command_id).one()
        assert row.status == STATUS_DONE
        assert row.coa_code == 41

    def test_apply_coa_result_unknown_id_silently_acks(self, app):
        from app.services.coa_disconnect import apply_coa_result
        outcome = apply_coa_result(command_id="not-a-real-id", status="done")
        assert outcome.found is False

    def test_alive_commands_expires_old_rows(self, app):
        """TTL elapsed → row transitions to expired + drops out of the
        alive list. We force the row's created_at into the past."""
        from datetime import datetime, timedelta
        from app.extensions import db as _db
        from app.models import PendingCoaCommand
        from app.services.coa_disconnect import (
            STATUS_EXPIRED, alive_commands, enqueue_coa_disconnect,
        )
        c = enqueue_coa_disconnect(realm="r-old", target_node_id=1)
        row = PendingCoaCommand.query.filter_by(command_id=c.command_id).one()
        row.created_at = datetime.utcnow() - timedelta(seconds=10_000)
        _db.session.add(row); _db.session.commit()

        alive = alive_commands(ttl_seconds=300)
        assert all(r.command_id != c.command_id for r in alive)
        row = PendingCoaCommand.query.filter_by(command_id=c.command_id).one()
        assert row.status == STATUS_EXPIRED


# ════════════════════════════════════════════════════════════════════════
# POST /api/proxy/coa-result — HTTP-level contract the proxy speaks
# ════════════════════════════════════════════════════════════════════════
class TestCoaResultEndpoint:
    """Hits the real Flask route with a signed X-Proxy-Token, asserting
    the wire contract proxy-side code will integrate against."""

    SECRET = "coa-result-test-secret-xxxxxxxxxxxxxx"

    def _sign(self) -> dict:
        import hashlib, hmac as _hmac, time, uuid as _uuid
        ts = int(time.time())
        nonce = _uuid.uuid4().hex
        mac = _hmac.new(
            self.SECRET.encode(), f"{ts}:{nonce}".encode(), hashlib.sha256,
        ).hexdigest()
        return {"X-Proxy-Token": f"{ts}:{nonce}:{mac}"}

    @pytest.fixture()
    def proxy_app(self, app):
        app.config["RADIUS_PROXY_SHARED_SECRET"] = self.SECRET
        app.config["RADIUS_PROXY_TOKEN_TTL"] = 60
        from app.api import proxy_api
        proxy_api._NONCE_CACHE.clear()
        return app

    def test_unauthorized_without_token(self, proxy_app, client):
        resp = client.post(
            "/api/proxy/coa-result",
            json={"id": "x", "status": "done"},
        )
        assert resp.status_code == 401

    def test_done_marks_row(self, proxy_app, client):
        from app.models import PendingCoaCommand
        from app.services.coa_disconnect import (
            STATUS_DONE, enqueue_coa_disconnect,
        )
        c = enqueue_coa_disconnect(realm="r-h1", target_node_id=1)

        resp = client.post(
            "/api/proxy/coa-result",
            json={"id": c.command_id, "status": "done", "coa_code": 41,
                  "detail": "Disconnect-ACK"},
            headers=self._sign(),
        )
        assert resp.status_code == 200, resp.get_data(as_text=True)
        body = resp.get_json()
        assert body["ok"] is True
        assert body["found"] is True
        assert body["already_terminal"] is False
        assert body["status"] == STATUS_DONE

        row = PendingCoaCommand.query.filter_by(command_id=c.command_id).one()
        assert row.status == STATUS_DONE
        assert row.coa_code == 41

    def test_failed_marks_row(self, proxy_app, client):
        from app.models import PendingCoaCommand
        from app.services.coa_disconnect import (
            STATUS_FAILED, enqueue_coa_disconnect,
        )
        c = enqueue_coa_disconnect(realm="r-h2", target_node_id=2)
        resp = client.post(
            "/api/proxy/coa-result",
            json={"id": c.command_id, "status": "failed", "coa_code": 42,
                  "detail": "NAK"},
            headers=self._sign(),
        )
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["status"] == STATUS_FAILED
        row = PendingCoaCommand.query.filter_by(command_id=c.command_id).one()
        assert row.coa_code == 42

    def test_unknown_id_silently_acks(self, proxy_app, client):
        resp = client.post(
            "/api/proxy/coa-result",
            json={"id": "doesnt-exist", "status": "done"},
            headers=self._sign(),
        )
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["ok"] is True
        assert body["found"] is False

    def test_bad_status_rejected(self, proxy_app, client):
        resp = client.post(
            "/api/proxy/coa-result",
            json={"id": "abc", "status": "weird"},
            headers=self._sign(),
        )
        assert resp.status_code == 400

    def test_missing_id_rejected(self, proxy_app, client):
        resp = client.post(
            "/api/proxy/coa-result",
            json={"status": "done"},
            headers=self._sign(),
        )
        assert resp.status_code == 400

    def test_re_report_terminal_is_idempotent(self, proxy_app, client):
        """The proxy retries POSTs on transient network errors. Re-
        reporting a row already done must NOT flip + must return 200."""
        from app.services.coa_disconnect import enqueue_coa_disconnect
        c = enqueue_coa_disconnect(realm="r-h3", target_node_id=3)
        client.post(
            "/api/proxy/coa-result",
            json={"id": c.command_id, "status": "done", "coa_code": 41},
            headers=self._sign(),
        )
        resp = client.post(
            "/api/proxy/coa-result",
            json={"id": c.command_id, "status": "failed", "coa_code": 42,
                  "detail": "retry"},
            headers=self._sign(),
        )
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["found"] is True
        assert body["already_terminal"] is True


# ════════════════════════════════════════════════════════════════════════
# GET /api/proxy/routing-table — pending_coa publish envelope
# ════════════════════════════════════════════════════════════════════════
class TestRoutingTablePendingCoa:
    """The routing-table response now carries a top-level pending_coa
    array. Mirrors the customer-radius-tunnel proxy_app fixture so the
    HMAC verifier passes."""

    SECRET = "routing-table-test-secret-xxxxxxxxxxxx"

    def _sign(self) -> dict:
        import hashlib, hmac as _hmac, time, uuid as _uuid
        ts = int(time.time())
        nonce = _uuid.uuid4().hex
        mac = _hmac.new(
            self.SECRET.encode(), f"{ts}:{nonce}".encode(), hashlib.sha256,
        ).hexdigest()
        return {"X-Proxy-Token": f"{ts}:{nonce}:{mac}"}

    @pytest.fixture()
    def proxy_app(self, app):
        app.config["RADIUS_PROXY_SHARED_SECRET"] = self.SECRET
        app.config["RADIUS_PROXY_TOKEN_TTL"] = 60
        from app.api import proxy_api
        proxy_api._NONCE_CACHE.clear()
        return app

    def test_pending_coa_top_level_envelope_present(self, proxy_app, client):
        """Even with an empty queue the field MUST be present so the
        proxy can rely on a stable contract."""
        resp = client.get("/api/proxy/routing-table", headers=self._sign())
        assert resp.status_code == 200
        body = resp.get_json()
        assert "pending_coa" in body
        assert body["pending_coa"] == []

    def test_pending_coa_lists_enqueued_command(self, proxy_app, client):
        from app.services.coa_disconnect import enqueue_coa_disconnect
        c = enqueue_coa_disconnect(
            realm="client50", target_node_id=50, reason="panel:chr-move",
        )
        resp = client.get("/api/proxy/routing-table", headers=self._sign())
        body = resp.get_json()
        ids = [row["id"] for row in body["pending_coa"]]
        assert c.command_id in ids
        row = next(r for r in body["pending_coa"] if r["id"] == c.command_id)
        assert row["realm"] == "client50"
        assert row["action"] == "disconnect"
        assert row["target_node_id"] == 50
        assert row["reason"] == "panel:chr-move"

    def test_pending_coa_transitions_pending_to_sent_on_publish(self, proxy_app, client):
        """The side-effect that lets the UI tell «بانتظار الاستلام»
        from «أُرسل، بانتظار التنفيذ»."""
        from app.models import PendingCoaCommand
        from app.services.coa_disconnect import enqueue_coa_disconnect

        c = enqueue_coa_disconnect(realm="client51", target_node_id=51)
        row = PendingCoaCommand.query.filter_by(command_id=c.command_id).one()
        assert row.status == STATUS_PENDING

        client.get("/api/proxy/routing-table", headers=self._sign())

        row = PendingCoaCommand.query.filter_by(command_id=c.command_id).one()
        assert row.status == STATUS_SENT
        assert row.picked_up_at is not None

    def test_pending_coa_drops_done_command(self, proxy_app, client):
        from app.services.coa_disconnect import (
            apply_coa_result, enqueue_coa_disconnect,
        )
        c = enqueue_coa_disconnect(realm="client52", target_node_id=52)
        apply_coa_result(command_id=c.command_id, status="done", coa_code=41)

        resp = client.get("/api/proxy/routing-table", headers=self._sign())
        ids = [row["id"] for row in resp.get_json()["pending_coa"]]
        assert c.command_id not in ids
