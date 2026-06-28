"""The customer file (المشترك / customer 360) must ENUMERATE all of the
customer's radius-panel admins AND expose the management control (force-super).

This regressed once: the detail-page redesign (detail_new.html) dropped the
«أدمن الراديوس» section and rendered the imported admin snapshot as an empty
«أجهزة NAS» table (with NAS fields the snapshot doesn't have) and no controls.
These tests pin that the section is back: every CustomerRadiusAdmin row is
listed, and a super-admin operator sees the force-super toggle for each.
"""
from __future__ import annotations

import pytest

from app.extensions import db
from app.models import Admin, Customer, CustomerRadiusAdmin


@pytest.fixture()
def customer_with_admins(app):
    c = Customer(company_name="Admins Co", email="admins@example.com", status="active")
    db.session.add(c)
    db.session.flush()
    db.session.add_all([
        CustomerRadiusAdmin(customer_id=c.id, radius_admin_id=1, username="root",
                            role="super_admin", is_super_admin=True, is_primary=True,
                            enabled=True),
        CustomerRadiusAdmin(customer_id=c.id, radius_admin_id=2, username="manager1",
                            role="manager", force_super=True, enabled=True,
                            managed_by_license_admin=True,
                            external_identity_provider="license_admin"),
        CustomerRadiusAdmin(customer_id=c.id, radius_admin_id=3, username="viewer1",
                            role="viewer", enabled=False),
    ])
    db.session.commit()
    return c


def _login_super(client):
    admin = Admin.query.first()
    with client.session_transaction() as s:
        s["admin_id"] = admin.id
        s["is_super_admin"] = True
    return client


def test_customer_file_enumerates_all_radius_admins(app, client, customer_with_admins):
    c = customer_with_admins
    _login_super(client)
    body = client.get(f"/admin/customers/{c.id}").get_data(as_text=True)
    assert "id=\"radius-admins\"" in body            # the dedicated section
    for username in ("root", "manager1", "viewer1"):  # ALL admins listed
        assert username in body


def test_customer_file_exposes_force_super_control(app, client, customer_with_admins):
    c = customer_with_admins
    _login_super(client)
    body = client.get(f"/admin/customers/{c.id}").get_data(as_text=True)
    # the per-row management control points at the existing force-super route.
    assert f"/customers/{c.id}/radius-admins/" in body
    assert "اجعله سوبر يوزر" in body                 # enable control (normal rows)
    assert "إلغاء فرض السوبر" in body                # disable control (forced row)


def test_force_super_toggle_persists(app, client, customer_with_admins):
    c = customer_with_admins
    _login_super(client)
    row = CustomerRadiusAdmin.query.filter_by(customer_id=c.id, username="viewer1").one()
    assert row.force_super is False
    r = client.post(f"/admin/customers/{c.id}/radius-admins/{row.id}/super",
                    data={"action": "enable"}, follow_redirects=False)
    assert r.status_code in (301, 302)
    db.session.expire_all()
    assert db.session.get(CustomerRadiusAdmin, row.id).force_super is True
