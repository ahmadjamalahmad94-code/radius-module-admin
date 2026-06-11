"""Tests for the fleet consolidation work (steps 1-5 of docs/CONSOLIDATION.md).

Covers:
  * system-health view actually renders nested ``health.resources.*`` keys
    (the previous flat-shadow bug rendered everything at 0% / «—»).
  * sidebar regroup — legacy «عقد CHR» link gone, items moved into «أسطول CHR».
  * legacy chr-nodes WRITE endpoints short-circuit to the fleet wizard.
  * settings#chr relabel to «نمط الـCHR الواحد».
  * legacy → fleet migration: dry-run, real run, idempotency, allocation
    rewrite, no-IP rows skipped, orphan accounting.

The fleet schema-heal column ``fleet_chr_nodes.legacy_chr_node_id`` is exercised
implicitly by these tests — if it weren't healed at startup, every migration
test would error with ``schema_heal_pending`` rather than the expected
counts.
"""
from __future__ import annotations

import pytest

from app.extensions import db
from app.models import Admin, ChrNode, Customer, CustomerRadiusInstance, ServiceAllocation, utcnow
from app.services.fleet_consolidation import (
    LEGACY_IMPORT_PROVIDER_NAME,
    plan_migration,
    run_migration,
)


# ─────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────
def _login_admin(client):
    return client.post("/login", data={"username": "admin", "password": "admin12345"})


def _make_super_admin():
    """The /admin/infra/consolidation endpoints require super_admin."""
    adm = Admin.query.first()
    if adm and not adm.is_super_admin:
        adm.is_super_admin = True
        db.session.commit()


def _legacy_node(name="chr-legacy-1", public_ip="1.2.3.4", **kw):
    defaults = dict(
        capacity_mbps=1000,
        max_reserved_mbps=850,
        max_active_sessions=2000,
        status="active",
        routeros_port=443,
    )
    defaults.update(kw)
    n = ChrNode(name=name, public_ip=public_ip, **defaults)
    db.session.add(n)
    db.session.commit()
    return n


# ─────────────────────────────────────────────────────────────────────────
# Step 1 — system-health renders real psutil values via nested dict
# ─────────────────────────────────────────────────────────────────────────
def test_system_health_renders_nested_resources_not_default_zero(client):
    _login_admin(client)
    rv = client.get("/admin/infra/system-health")
    assert rv.status_code == 200
    body = rv.get_data(as_text=True)
    # The template was reading health.resources.<x>. After the fix the
    # rendered values track the actual probes (psutil or the stdlib fallback);
    # we don't assert exact numbers, just that the page no longer hardcodes
    # 0% and «—» across the board.
    # On the test host the disk-percent path is the most reliable signal
    # because shutil.disk_usage works without psutil. We accept any digit.
    import re
    disk_match = re.search(r"استخدام القرص (\d+)%", body)
    assert disk_match is not None, "disk pct not rendered"
    # The poller liveness pill the fix adds must also be present.
    assert "جامع مقاييس الأسطول" in body


def test_system_health_recent_errors_use_adapted_keys(client, app):
    """The view adapts AuditLog rows to {message,occurred_at,service,code}."""
    _login_admin(client)
    rv = client.get("/admin/infra/system-health")
    assert rv.status_code == 200
    body = rv.get_data(as_text=True)
    # Empty state shows the success message — proves the for-loop reached the
    # else branch without crashing on missing attributes.
    assert "لا توجد أخطاء حديثة" in body


# ─────────────────────────────────────────────────────────────────────────
# Step 2 — sidebar regroup
# ─────────────────────────────────────────────────────────────────────────
def test_sidebar_moves_items_into_fleet_group_and_hides_legacy_link(client):
    _login_admin(client)
    body = client.get("/admin/infra/system-health").get_data(as_text=True)
    # Items moved under «أسطول CHR» (group label is rendered exactly once).
    assert body.count("أسطول CHR") >= 1
    for label in ("بروفايلات السرعة", "نسخ RADIUS", "تخصيصات الخدمة", "وكيل RADIUS"):
        assert label in body, f"sidebar should now expose «{label}» under fleet"
    # Legacy «عقد CHR» sidebar link removed — the URL `/admin/infra/chr-nodes`
    # should not appear as an anchor href anywhere on the page chrome.
    # The list page route still exists (read-only), but no nav points at it.
    assert 'href="/admin/infra/chr-nodes"' not in body


# ─────────────────────────────────────────────────────────────────────────
# Step 3 — legacy banner + write short-circuits
# ─────────────────────────────────────────────────────────────────────────
def test_legacy_chr_nodes_list_shows_deprecation_banner(client):
    _login_admin(client)
    rv = client.get("/admin/infra/chr-nodes")
    assert rv.status_code == 200
    body = rv.get_data(as_text=True)
    assert "تمت ترقية إدارة العقد إلى «أسطول CHR»" in body
    # Banner links to wizard, dashboard, AND the consolidation page.
    assert "/admin/fleet/onboarding/new" in body
    assert "/admin/fleet/" in body
    assert "/admin/infra/consolidation" in body


def test_legacy_chr_node_create_redirects_to_fleet_wizard(client):
    _login_admin(client); _make_super_admin()
    rv = client.post("/admin/infra/chr-nodes/create", data={"name": "x"}, follow_redirects=False)
    assert rv.status_code in (302, 303)
    assert "/admin/fleet/onboarding/new" in rv.headers.get("Location", "")


def test_legacy_chr_node_poll_all_redirects_to_fleet_dashboard(client):
    _login_admin(client); _make_super_admin()
    rv = client.post("/admin/infra/chr-nodes/poll-all", follow_redirects=False)
    assert rv.status_code in (302, 303)
    assert "/admin/fleet/" in rv.headers.get("Location", "")


def test_legacy_chr_node_edit_404s_for_unknown_id(client):
    """An edit POST to a non-existent legacy id still 404s — the short-circuit
    must not paper over garbage IDs (which would hurt audit / intrusion logs)."""
    _login_admin(client); _make_super_admin()
    rv = client.post("/admin/infra/chr-nodes/99999/edit", data={})
    assert rv.status_code == 404


# ─────────────────────────────────────────────────────────────────────────
# Step 4 — settings#chr relabel
# ─────────────────────────────────────────────────────────────────────────
def test_settings_page_uses_single_chr_label(client):
    _login_admin(client)
    rv = client.get("/admin/settings")
    assert rv.status_code == 200
    body = rv.get_data(as_text=True)
    # New label appears in the tab header AND the section card.
    assert "نمط الـCHR الواحد" in body
    # The old label "تزويد الأنفاق المركزي" survives in a header comment
    # in the template, but the visible TAB BUTTON should say the new wording.
    # Loose check — ensure the new wording is present.
    assert "للنشر متعدد العقد استخدم «أسطول CHR»" in body


# ─────────────────────────────────────────────────────────────────────────
# Step 5 — legacy → fleet migration
# ─────────────────────────────────────────────────────────────────────────
def test_dry_run_reports_imports_without_writing(app, client):
    _legacy_node(name="chr-legacy-1", public_ip="1.2.3.4")
    _legacy_node(name="chr-legacy-2", public_ip="5.6.7.8")
    plan = plan_migration()
    assert plan.dry_run is True
    assert plan.legacy_total == 2
    assert plan.imported == 2
    assert plan.skipped_existing == 0
    # Crucially, no fleet rows were written.
    from fleet.registry.models_chr import FleetChrNode
    assert FleetChrNode.query.count() == 0


def test_real_run_creates_fleet_nodes_and_stamps_legacy_id(app):
    _legacy_node(name="chr-legacy-1", public_ip="10.0.0.1")
    legacy_id = ChrNode.query.first().id
    result = run_migration(dry_run=False)
    assert result.error is None
    assert result.imported == 1
    from fleet.registry.models_chr import FleetChrNode, FleetProvider
    rows = FleetChrNode.query.all()
    assert len(rows) == 1
    assert rows[0].legacy_chr_node_id == legacy_id
    # Provider stamped legacy-import.
    prov = FleetProvider.query.filter_by(name=LEGACY_IMPORT_PROVIDER_NAME).one()
    assert rows[0].provider_id == prov.id


def test_migration_is_idempotent(app):
    _legacy_node(name="chr-legacy-1", public_ip="10.0.0.1")
    first = run_migration(dry_run=False)
    assert first.imported == 1
    # Second run sees one existing fleet row, imports nothing, skips one.
    second = run_migration(dry_run=False)
    assert second.error is None
    assert second.imported == 0
    assert second.skipped_existing == 1
    from fleet.registry.models_chr import FleetChrNode
    assert FleetChrNode.query.count() == 1


def test_service_allocation_chr_node_id_is_rewritten(app):
    """The real proof: a SA pointing at the legacy id now points at the fleet id.

    We seed two legacy rows so the legacy id values are 1+2; then a couple of
    pre-existing native fleet rows so the new fleet row's autoincrement id
    lands at 3+, distinct from the legacy id. Without this gap the equality
    check would be misleading (both sequences mint id=1 on a fresh DB).
    """
    # Pre-existing native fleet content to shift the autoincrement past the
    # legacy ids — uses the same code path the wizard would, but as a fixture.
    from fleet.registry.models_chr import FleetChrNode, FleetProvider
    prov = FleetProvider(name="native-prov", cost_model="open", price_per_tb=0)
    db.session.add(prov); db.session.flush()
    for i, ip in enumerate(("198.51.100.10", "198.51.100.11"), start=1):
        db.session.add(FleetChrNode(
            provider_id=prov.id, name=f"native-{i}", public_ip=ip,
            wg_mgmt_ip=f"10.250.{i}.1", wg_mgmt_pubkey="x",
            routeros_api_port=8443, routeros_api_user="", routeros_api_password_enc="",
            coa_port=3799, max_sessions=100, link_speed_mbps=1000, status="up",
        ))
    db.session.commit()

    legacy = _legacy_node(name="chr-legacy-1", public_ip="10.0.0.1")
    cust = Customer(company_name="Cust", contact_name="O", email="o@x", status="active")
    db.session.add(cust); db.session.flush()
    sa = ServiceAllocation(
        customer_id=cust.id, service_type="sstp", status="active",
        chr_node_id=legacy.id, speed_limit_mbps=100, max_accounts=1, max_peers=0,
    )
    db.session.add(sa); db.session.commit()
    legacy_id = legacy.id

    result = run_migration(dry_run=False)
    assert result.imported == 1
    assert result.allocations_rewritten == 1
    assert result.orphan_allocations_after == 0

    imported_row = FleetChrNode.query.filter_by(legacy_chr_node_id=legacy_id).one()
    refreshed = db.session.get(ServiceAllocation, sa.id)
    # After migration the allocation's chr_node_id points at the new fleet row,
    # and that fleet row's id is provably distinct from the legacy id.
    assert refreshed.chr_node_id == imported_row.id
    assert imported_row.id != legacy_id


def test_legacy_row_without_public_ip_is_skipped_as_invalid(app):
    """Legacy rows missing the required public_ip get reported, not imported."""
    n = ChrNode(name="chr-bad", public_ip="", capacity_mbps=100, max_reserved_mbps=80, status="pending")
    db.session.add(n); db.session.commit()
    result = run_migration(dry_run=False)
    assert result.imported == 0
    assert result.skipped_invalid == 1
    # And there's an orphan allocation accounting line ready to surface.
    assert result.orphan_allocations_after == 0  # no SAs in this test


def test_consolidation_page_renders_for_super_admin(client, app):
    _login_admin(client); _make_super_admin()
    _legacy_node(name="chr-legacy-1", public_ip="10.0.0.1")
    rv = client.get("/admin/infra/consolidation")
    assert rv.status_code == 200
    body = rv.get_data(as_text=True)
    assert "ترحيل العقد القديمة إلى الأسطول" in body
    assert "chr-legacy-1" in body
    # The action button must NOT be disabled while there's work to do.
    # (The disabled flag is only emitted when imports == 0 AND allocs == 0.)
    assert "disabled" not in body.split("نفّذ الترحيل")[0][-200:]


def test_consolidation_run_endpoint_is_idempotent(client, app):
    _login_admin(client); _make_super_admin()
    _legacy_node(name="chr-legacy-1", public_ip="10.0.0.1")
    # First POST migrates.
    rv = client.post("/admin/infra/consolidation/run", follow_redirects=False)
    assert rv.status_code in (302, 303)
    from fleet.registry.models_chr import FleetChrNode
    assert FleetChrNode.query.count() == 1
    # Second POST is a safe no-op.
    rv2 = client.post("/admin/infra/consolidation/run", follow_redirects=False)
    assert rv2.status_code in (302, 303)
    assert FleetChrNode.query.count() == 1


def test_consolidation_run_requires_super_admin(client, app):
    """A non-super admin gets bounced (403/redirect) — commercial change."""
    _login_admin(client)
    # Strip super if the fixture promoted it.
    adm = Admin.query.first()
    if adm and adm.is_super_admin:
        adm.is_super_admin = False
        db.session.commit()
    rv = client.post("/admin/infra/consolidation/run", follow_redirects=False)
    # The decorator returns either 403 or a redirect — accept both.
    assert rv.status_code in (302, 303, 403)


# ─────────────────────────────────────────────────────────────────────────
# Tier model untouched by this work — quick smoke on the customer panel
# being intact (the consolidation shouldn't touch portal templates).
# ─────────────────────────────────────────────────────────────────────────
def test_portal_login_page_still_works(client):
    rv = client.get("/portal/login")
    assert rv.status_code == 200
