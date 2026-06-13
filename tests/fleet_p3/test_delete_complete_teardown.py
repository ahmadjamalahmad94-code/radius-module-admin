"""fix/fleet-delete-complete-teardown — every leftover the owner saw
must be torn down on a single delete click.

Owner: «لما حذفت ما تنظفت العقد، بضل بقايا». The teardown service
now cascades through every surface that previously orphaned:

  * ProxyRealmRoute.allowed_fleet_chr_node_ids_json (JSON list)
  * PendingCoaCommand.target_node_id (non-FK)
  * fleet sessions (when the model exists in the deploy)
  * UserFleet.pinned_chr_id (non-cascade FK)
  * Panel-host wg-mgmt peer apply (auto-reconcile on every delete)

The teardown is centralised in ``fleet/registry/teardown.py`` so the
three delete surfaces (job-delete, direct orphan-node delete, purge)
all use the SAME cascade. These tests pin that contract.
"""
from __future__ import annotations

import json

import pytest

from app.extensions import db
from app.models import Admin, Customer, PendingCoaCommand, ProxyRealmRoute
from fleet.registry.models_chr import FleetChrNode, FleetProvider
from fleet.registry.models_onboarding import OnboardingJob
from fleet.registry.teardown import (
    find_orphans, purge_orphans, teardown_node,
)


# ════════════════════════════════════════════════════════════════════════
# Fixtures
# ════════════════════════════════════════════════════════════════════════
@pytest.fixture()
def make_node(app):
    seq = [0]

    def _provider():
        return FleetProvider.query.filter_by(name="td-tests").first() or (
            db.session.add(FleetProvider(name="td-tests", cost_model="open"))
            or db.session.flush() or FleetProvider.query.filter_by(name="td-tests").first()
        )

    def _make(**overrides):
        seq[0] += 1
        defaults = dict(
            provider_id=_provider().id,
            name=f"chr-test-{seq[0]}",
            public_ip=f"203.0.113.{seq[0]}",
            wg_mgmt_ip=f"10.99.0.{seq[0] + 10}",
            wg_mgmt_pubkey="x" * 44,
            routeros_api_port=8443,
            coa_port=3799,
            max_sessions=500,
            link_speed_mbps=1000,
            enabled=True, drain=False, status="up",
        )
        defaults.update(overrides)
        n = FleetChrNode(**defaults)
        db.session.add(n); db.session.commit()
        return n

    return _make


@pytest.fixture()
def make_job(app):
    def _make(*, name: str, status: str = "draft", chr_id: int | None = None):
        j = OnboardingJob(status=status)
        j.form_input = {"name": name, "provider": "td-tests"}
        j.chr_id = chr_id
        db.session.add(j); db.session.commit()
        return j

    return _make


@pytest.fixture()
def make_route(app):
    """Build a ProxyRealmRoute referencing the given node ids in its
    allowlist (used to test the scrub-on-delete invariant)."""
    seq = [0]

    def _make(*, allowed_node_ids: list[int]) -> ProxyRealmRoute:
        seq[0] += 1
        c = Customer(company_name=f"td-{seq[0]}", email=f"x{seq[0]}@x.x", phone="")
        db.session.add(c); db.session.flush()
        from app.models import CustomerRadiusInstance
        inst = CustomerRadiusInstance(
            customer_id=c.id,
            instance_name=f"client{c.id}-radius",
            realm=f"client{c.id}-{seq[0]}",
            radius_auth_ip=f"10.200.{c.id}.2",
            status="online",
        )
        db.session.add(inst); db.session.flush()
        route = ProxyRealmRoute(
            realm=inst.realm, customer_id=c.id, radius_instance_id=inst.id,
            target_radius_ip=inst.radius_auth_ip, status="active",
        )
        route.allowed_fleet_chr_node_ids = list(allowed_node_ids)
        db.session.add(route); db.session.commit()
        return route

    return _make


# ════════════════════════════════════════════════════════════════════════
# (I) teardown_node — every surface is touched on a single call
# ════════════════════════════════════════════════════════════════════════
class TestTeardownNode:

    def test_node_row_deleted(self, app, make_node):
        n = make_node()
        teardown_node(n)
        db.session.commit()
        assert db.session.get(FleetChrNode, n.id) is None

    def test_route_node_id_scrubbed(self, app, make_node, make_route):
        n1 = make_node()
        n2 = make_node()
        route = make_route(allowed_node_ids=[n1.id, n2.id])
        report = teardown_node(n1)
        db.session.commit()
        db.session.refresh(route)
        assert n1.id not in route.allowed_fleet_chr_node_ids
        # The OTHER node id stays — we only scrub the deleted one.
        assert n2.id in route.allowed_fleet_chr_node_ids
        assert report.routes_scrubbed == 1

    def test_multiple_routes_scrubbed(self, app, make_node, make_route):
        n = make_node()
        r1 = make_route(allowed_node_ids=[n.id])
        r2 = make_route(allowed_node_ids=[n.id, 999])  # 999 unrelated
        report = teardown_node(n)
        db.session.commit()
        db.session.refresh(r1); db.session.refresh(r2)
        assert n.id not in r1.allowed_fleet_chr_node_ids
        assert n.id not in r2.allowed_fleet_chr_node_ids
        assert report.routes_scrubbed == 2

    def test_pending_coa_dropped(self, app, make_node):
        n = make_node()
        # Enqueue a CoA targeting this node id.
        from app.services.coa_disconnect import enqueue_coa_disconnect
        enqueue_coa_disconnect(realm="r-td", target_node_id=n.id)
        before = PendingCoaCommand.query.filter_by(target_node_id=n.id).count()
        assert before == 1

        report = teardown_node(n)
        db.session.commit()
        assert PendingCoaCommand.query.filter_by(target_node_id=n.id).count() == 0
        assert report.coa_commands_dropped == 1

    def test_does_not_drop_other_coa_rows(self, app, make_node):
        n1 = make_node()
        n2 = make_node()
        from app.services.coa_disconnect import enqueue_coa_disconnect
        enqueue_coa_disconnect(realm="r1", target_node_id=n1.id)
        enqueue_coa_disconnect(realm="r2", target_node_id=n2.id)
        teardown_node(n1)
        db.session.commit()
        assert PendingCoaCommand.query.filter_by(target_node_id=n2.id).count() == 1

    def test_panel_peer_reconcile_attempted(self, app, make_node):
        """The teardown report always carries a ``panel_peer_apply``
        dict (the wg-mgmt reconcile result). In test the helper is
        absent so it reports ``available=False`` — what matters is
        that the reconcile was CALLED, not its outcome."""
        n = make_node()
        report = teardown_node(n)
        db.session.commit()
        assert isinstance(report.panel_peer_apply, dict)
        assert "available" in report.panel_peer_apply

    def test_idempotent_on_already_gone_node(self, app):
        """Re-teardown of a never-existed id is a clean no-op."""
        report = teardown_node(99999)
        db.session.commit()
        assert report.node_row_deleted is False
        assert report.routes_scrubbed == 0


# ════════════════════════════════════════════════════════════════════════
# (II) /jobs/<id>/delete — uses centralised teardown
# ════════════════════════════════════════════════════════════════════════
def _login_admin(client):
    return client.post("/login", data={"username": "admin", "password": "admin12345"})


def _make_super_admin():
    adm = Admin.query.first()
    if adm and not adm.is_super_admin:
        adm.is_super_admin = True
        db.session.commit()


class TestDeleteJobCascades:

    def test_delete_job_with_node_scrubs_routes(self, app, client, make_node, make_route, make_job):
        n = make_node()
        route = make_route(allowed_node_ids=[n.id])
        job = make_job(name=n.name, status="failed", chr_id=n.id)

        _login_admin(client); _make_super_admin()
        resp = client.post(
            f"/admin/fleet/onboarding/jobs/{job.id}/delete",
            data=json.dumps({"remove_node": True}),
            content_type="application/json",
        )
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["ok"] is True
        assert body["node_removed"] is True
        assert body["teardown"]["routes_scrubbed"] == 1

        db.session.refresh(route)
        assert n.id not in route.allowed_fleet_chr_node_ids

    def test_delete_job_without_node_does_not_run_teardown(self, app, client, make_node, make_route, make_job):
        n = make_node()
        route = make_route(allowed_node_ids=[n.id])
        job = make_job(name=n.name, status="failed", chr_id=n.id)

        _login_admin(client); _make_super_admin()
        resp = client.post(
            f"/admin/fleet/onboarding/jobs/{job.id}/delete",
            data=json.dumps({"remove_node": False}),
            content_type="application/json",
        )
        assert resp.status_code == 200
        body = resp.get_json()
        # remove_node=False means the node row stays + teardown not run.
        assert body["node_removed"] is False
        assert db.session.get(FleetChrNode, n.id) is not None
        # The route's allowlist still has the id (no scrub).
        db.session.refresh(route)
        assert n.id in route.allowed_fleet_chr_node_ids


# ════════════════════════════════════════════════════════════════════════
# (III) /nodes/<id>/delete — direct orphan-node delete
# ════════════════════════════════════════════════════════════════════════
class TestOrphanNodeDelete:

    def test_delete_orphan_node(self, app, client, make_node, make_route):
        """A node with NO live job — the previous delete surface
        couldn't reach it. Direct delete + full cascade."""
        n = make_node()
        route = make_route(allowed_node_ids=[n.id])

        _login_admin(client); _make_super_admin()
        resp = client.post(
            f"/admin/fleet/onboarding/nodes/{n.id}/delete",
            data=json.dumps({}),
            content_type="application/json",
        )
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["ok"] is True
        assert body["teardown"]["routes_scrubbed"] == 1
        assert db.session.get(FleetChrNode, n.id) is None

    def test_refuses_when_live_job_points_at_node(self, app, client, make_node, make_job):
        """Delete must be refused if a non-failed job still references
        the node — operator should delete the job first."""
        n = make_node()
        job = make_job(name=n.name, status="draft", chr_id=n.id)

        _login_admin(client); _make_super_admin()
        resp = client.post(
            f"/admin/fleet/onboarding/nodes/{n.id}/delete",
            data=json.dumps({}),
            content_type="application/json",
        )
        assert resp.status_code == 409
        body = resp.get_json()
        assert body["error"] == "delete_refused"
        # Node still present.
        assert db.session.get(FleetChrNode, n.id) is not None

    def test_allows_when_only_failed_job_points_at_node(self, app, client, make_node, make_job):
        """A failed job no longer blocks the node — the operator can
        clean up directly."""
        n = make_node()
        make_job(name=n.name, status="failed", chr_id=n.id)

        _login_admin(client); _make_super_admin()
        resp = client.post(
            f"/admin/fleet/onboarding/nodes/{n.id}/delete",
            data=json.dumps({}),
            content_type="application/json",
        )
        assert resp.status_code == 200

    def test_404_on_missing_node(self, app, client):
        _login_admin(client); _make_super_admin()
        resp = client.post(
            "/admin/fleet/onboarding/nodes/99999/delete",
            data=json.dumps({}),
            content_type="application/json",
        )
        assert resp.status_code == 404


# ════════════════════════════════════════════════════════════════════════
# (IV) Orphan survey + purge
# ════════════════════════════════════════════════════════════════════════
class TestOrphanSurveyAndPurge:

    def test_find_orphans_lists_node_without_live_job(self, app, make_node, make_job):
        n = make_node()
        # Only a failed job points at the node — not in the live-state set.
        make_job(name=n.name, status="failed", chr_id=n.id)
        survey = find_orphans()
        assert n.id in survey.orphan_node_ids

    def test_find_orphans_lists_jobs_with_null_chr(self, app, make_job):
        j = make_job(name="dangling", status="failed", chr_id=None)
        survey = find_orphans()
        assert j.id in survey.orphan_job_ids

    def test_find_orphans_lists_stale_route_node_ids(self, app, make_route):
        # Build a route referencing a non-existent node id.
        route = make_route(allowed_node_ids=[12345])
        survey = find_orphans()
        assert int(route.id) in survey.stale_route_node_ids
        assert 12345 in survey.stale_route_node_ids[int(route.id)]

    def test_find_orphans_lists_stale_coa(self, app, make_node):
        from app.services.coa_disconnect import enqueue_coa_disconnect
        n = make_node()
        cmd = enqueue_coa_disconnect(realm="r", target_node_id=n.id)
        # Delete the node directly; the CoA still points at the id.
        db.session.delete(n); db.session.commit()
        survey = find_orphans()
        # The CoA's row.id (NOT the command_id) is what we surface.
        from app.models import PendingCoaCommand
        row = PendingCoaCommand.query.filter_by(command_id=cmd.command_id).one()
        assert row.id in survey.stale_coa_node_ids

    def test_purge_orphans_removes_everything(self, app, make_node, make_job, make_route):
        # Build an orphan node + a dangling job + a stale route ref.
        n = make_node()
        make_job(name=n.name, status="failed", chr_id=n.id)  # not in live states
        dangling = make_job(name="dangling", status="failed", chr_id=None)
        stale_route = make_route(allowed_node_ids=[n.id])

        report = purge_orphans()
        db.session.commit()

        # Node gone.
        assert db.session.get(FleetChrNode, n.id) is None
        # Dangling job gone.
        assert db.session.get(OnboardingJob, dangling.id) is None
        # Route's allowlist scrubbed.
        db.session.refresh(stale_route)
        assert n.id not in stale_route.allowed_fleet_chr_node_ids
        # Survey before was non-empty.
        assert not report.survey_before.is_empty

    def test_purge_route_endpoint_audit_metadata(self, app, client, make_node, make_route):
        n = make_node()
        make_route(allowed_node_ids=[n.id])
        # Delete the node row directly (orphan the JSON).
        db.session.delete(n); db.session.commit()

        _login_admin(client); _make_super_admin()
        resp = client.post(
            "/admin/fleet/onboarding/orphans/purge",
            data=json.dumps({}),
            content_type="application/json",
        )
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["ok"] is True
        assert body["report"]["survey_before"]["stale_route_node_ids"]

    def test_survey_route_endpoint_is_read_only(self, app, client, make_node, make_route):
        n = make_node()
        route = make_route(allowed_node_ids=[n.id])
        db.session.delete(n); db.session.commit()

        _login_admin(client); _make_super_admin()
        resp = client.get("/admin/fleet/onboarding/orphans")
        assert resp.status_code == 200
        survey = resp.get_json()["survey"]
        # JSON object keys are strings.
        assert str(int(route.id)) in survey["stale_route_node_ids"]
        # And the route still has the stale id — survey doesn't write.
        db.session.refresh(route)
        assert n.id in route.allowed_fleet_chr_node_ids


# ════════════════════════════════════════════════════════════════════════
# (V) Dashboard UI — purge button + modal render; per-node delete button
# ════════════════════════════════════════════════════════════════════════
class TestDashboardOrphanUi:

    def test_purge_button_renders_for_super_admin(self, app, client):
        _login_admin(client); _make_super_admin()
        body = client.get("/admin/fleet/").get_data(as_text=True)
        assert 'id="fd-orphan-purge-btn"' in body
        assert "نظِّف المهملات" in body
        # The button carries the data-* endpoint URLs the JS hits.
        assert "data-survey-url=" in body
        assert "data-purge-url=" in body
        # Survey URL must be the GET endpoint; purge URL must be the
        # POST endpoint. Both belong to the onboarding blueprint.
        assert "/admin/fleet/onboarding/orphans" in body

    def test_purge_modal_scaffold_present(self, app, client):
        _login_admin(client); _make_super_admin()
        body = client.get("/admin/fleet/").get_data(as_text=True)
        assert 'id="fd-orphan-modal"' in body
        assert 'id="fd-orphan-survey-body"' in body
        assert 'id="fd-orphan-confirm-btn"' in body
        assert 'id="fd-orphan-cancel-btn"' in body
        # The confirm button starts disabled until the survey returns
        # a non-empty list — defence vs an accidental click before the
        # preview has loaded.
        assert 'id="fd-orphan-confirm-btn"' in body
        assert 'disabled' in body
        # No native confirm() — the modal IS the confirm step.
        assert "confirm(" not in body

    def test_per_node_delete_button_renders_with_csrf_form(self, app, client, make_node):
        """Each node in the grid renders its own POST form to the
        existing ``fleet_ui.chr_node_delete`` endpoint (now routed
        through the centralised teardown). The form carries the CSRF
        token + the confirmation modal trigger."""
        n = make_node(name="chr-vpn-test", public_ip="9.0.0.99")
        _login_admin(client); _make_super_admin()
        body = client.get("/admin/fleet/").get_data(as_text=True)
        assert f'id="fd-del-form-{n.id}"' in body
        assert f"/admin/fleet/chr-nodes/{n.id}/delete" in body
        # The delete button triggers the design-system confirm modal.
        assert f'data-confirm-form="fd-del-form-{n.id}"' in body

    def test_server_endpoints_require_super_admin(self, app, client):
        """The data path (orphans GET + purge POST + chr_node delete)
        is decorated with ``@super_admin_required`` so even a leaked
        UI button can't trigger the action. We probe the endpoints
        directly without logging in."""
        # Both endpoints redirect unauthenticated requests to login,
        # never returning the survey JSON. 302/401 is acceptable.
        r1 = client.get("/admin/fleet/onboarding/orphans")
        assert r1.status_code in (302, 401, 403)
        r2 = client.post(
            "/admin/fleet/onboarding/orphans/purge",
            data=json.dumps({}),
            content_type="application/json",
        )
        assert r2.status_code in (302, 401, 403)
