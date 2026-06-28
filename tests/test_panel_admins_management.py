"""Provider-side FULL management of a customer's panel admins —
feat/panel-admins-full-mgmt.

From the customer file (customer 360, network tab) the licensing owner manages
the customer's radius-panel admins end to end: SEE them (snapshot), ADD a new
admin, EDIT its permissions (role), and DELETE it (safe deactivate). The desired
state lives in ``CustomerManagedAdmin`` and rides the EXISTING signed pull bridge
as declarative ``admin_directives`` inside the identity-sync contract.

This module proves the PROVIDER side:
  • add → a managed row + an ``upsert`` directive carrying the werkzeug hash once.
  • the initial password is never stored/echoed in plaintext.
  • edit role → directive role_key changes; the page surfaces it.
  • deactivate → ``deactivate`` directive; GUARDS block deleting a designated
    owner and the last remaining enabled admin.
  • provisioned flip (admin observed in the reverse snapshot) drops the hash.
  • every action is super-admin gated.
"""
from __future__ import annotations

from datetime import timedelta

import pytest

from app.extensions import db
from app.models import (
    Admin,
    Customer,
    CustomerManagedAdmin,
    CustomerRadiusAdmin,
    License,
    Plan,
    utcnow,
)
from app.services.customer_control import (
    build_identity_sync_contract,
    import_radius_admins,
)


@pytest.fixture()
def cust_lic(app):
    plan = Plan.query.filter_by(slug="pro").one()
    c = Customer(company_name="Admins Mgmt Co", email="am@example.com", status="active")
    db.session.add(c)
    db.session.flush()
    lic = License(customer_id=c.id, plan_id=plan.id, license_key="LIC-ADMINS-MGMT",
                  status="active", starts_at=utcnow() - timedelta(days=1),
                  expires_at=utcnow() + timedelta(days=365),
                  grace_until=utcnow() + timedelta(days=372))
    db.session.add(lic)
    # a pre-existing local admin in the reverse snapshot (so the customer is never
    # left with zero admins — exercises the last-admin guard realistically).
    db.session.add(CustomerRadiusAdmin(customer_id=c.id, radius_admin_id=1,
                                       username="root", role="super_admin",
                                       is_primary=True, enabled=True))
    db.session.commit()
    return c, lic


def _login_super(client):
    admin = Admin.query.first()
    with client.session_transaction() as s:
        s["admin_id"] = admin.id
        s["is_super_admin"] = True
    return client


def _directives(lic):
    return build_identity_sync_contract(lic, license_active=True, status="active")["admin_directives"]


def _by_username(directives, username):
    for d in directives:
        if d["username"] == username:
            return d
    return None


# ── default: identity contract carries an (empty) admin_directives list ───────
def test_admin_directives_empty_by_default(cust_lic):
    _c, lic = cust_lic
    assert _directives(lic) == []


# ── ADD: managed row + upsert directive carrying the hash ONCE ───────────────
def test_add_admin_creates_directive(app, client, cust_lic):
    c, lic = cust_lic
    _login_super(client)
    r = client.post(f"/admin/customers/{c.id}/panel-admins/add",
                    data={"username": "newadmin", "password": "Sup3rSecret", "role_key": "admin"},
                    follow_redirects=False)
    assert r.status_code in (301, 302)
    db.session.expire_all()
    row = CustomerManagedAdmin.query.filter_by(customer_id=c.id, username="newadmin").one()
    assert row.active is True and row.role_key == "admin"
    # password is hashed (werkzeug), never the plaintext.
    assert row.password_hash and "Sup3rSecret" not in row.password_hash
    assert row.password_hash.startswith(("scrypt:", "pbkdf2:"))
    assert row.must_change_password is True and row.password_provisioned is False
    d = _by_username(_directives(lic), "newadmin")
    assert d and d["op"] == "upsert" and d["role_key"] == "admin"
    assert d["password_hash"] == row.password_hash
    assert d["password_hash_scheme"] == "werkzeug" and d["must_change_password"] is True


def test_add_admin_appears_on_customer_file(app, client, cust_lic):
    c, _lic = cust_lic
    _login_super(client)
    client.post(f"/admin/customers/{c.id}/panel-admins/add",
                data={"username": "pendingadmin", "password": "Sup3rSecret", "role_key": "support"})
    body = client.get(f"/admin/customers/{c.id}").get_data(as_text=True)
    assert "pendingadmin" in body
    assert "قيد الإنشاء" in body          # pending-creation badge


# ── EDIT permissions: role change reflected in the directive ─────────────────
def test_edit_permissions(app, client, cust_lic):
    c, lic = cust_lic
    _login_super(client)
    client.post(f"/admin/customers/{c.id}/panel-admins/add",
                data={"username": "newadmin", "password": "Sup3rSecret", "role_key": "viewer"})
    client.post(f"/admin/customers/{c.id}/panel-admins/role",
                data={"username": "newadmin", "role_key": "billing"})
    db.session.expire_all()
    d = _by_username(_directives(lic), "newadmin")
    assert d["role_key"] == "billing"


# ── EDIT a local (snapshot-only) admin adopts it under management ────────────
def test_edit_local_admin_adopts_it(app, client, cust_lic):
    c, lic = cust_lic
    _login_super(client)
    # 'root' exists only in the reverse snapshot — editing its role adopts it.
    client.post(f"/admin/customers/{c.id}/panel-admins/role",
                data={"username": "root", "role_key": "support"})
    db.session.expire_all()
    d = _by_username(_directives(lic), "root")
    assert d and d["op"] == "upsert" and d["role_key"] == "support"


# ── DELETE = safe deactivate → deactivate directive ──────────────────────────
def test_deactivate_admin(app, client, cust_lic):
    c, lic = cust_lic
    _login_super(client)
    client.post(f"/admin/customers/{c.id}/panel-admins/add",
                data={"username": "newadmin", "password": "Sup3rSecret", "role_key": "admin"})
    client.post(f"/admin/customers/{c.id}/panel-admins/deactivate",
                data={"username": "newadmin"})
    db.session.expire_all()
    row = CustomerManagedAdmin.query.filter_by(customer_id=c.id, username="newadmin").one()
    assert row.active is False
    d = _by_username(_directives(lic), "newadmin")
    assert d["op"] == "deactivate" and d["active"] is False
    assert "password_hash" not in d            # never ship a hash on deactivate


# ── GUARD: cannot deactivate a designated owner ──────────────────────────────
def test_guard_cannot_delete_owner(app, client, cust_lic):
    c, _lic = cust_lic
    _login_super(client)
    # add a second admin so 'root' is not the *last* one (isolate the owner guard).
    client.post(f"/admin/customers/{c.id}/panel-admins/add",
                data={"username": "second", "password": "Sup3rSecret", "role_key": "admin"})
    client.post(f"/admin/customers/{c.id}/owner-admins",
                data={"action": "save", "owner_admins": "root"})
    db.session.expire_all()
    r = client.post(f"/admin/customers/{c.id}/panel-admins/deactivate",
                    data={"username": "root"}, follow_redirects=True)
    assert "لا يمكن تعطيل حساب «مالك»" in r.get_data(as_text=True)
    # 'root' was never adopted as deactivated.
    row = CustomerManagedAdmin.query.filter_by(customer_id=c.id, username="root").first()
    assert row is None or row.active is True


# ── GUARD: cannot deactivate the last remaining enabled admin ────────────────
def test_guard_cannot_delete_last_admin(app, client, cust_lic):
    c, _lic = cust_lic
    _login_super(client)
    # only 'root' exists (from the fixture snapshot) → deactivating it is blocked.
    r = client.post(f"/admin/customers/{c.id}/panel-admins/deactivate",
                    data={"username": "root"}, follow_redirects=True)
    assert "آخِر أدمن مفعّل" in r.get_data(as_text=True)


# ── provisioned flip: once observed in the snapshot, stop shipping the hash ──
def test_provisioned_flip_drops_hash(app, client, cust_lic):
    c, lic = cust_lic
    _login_super(client)
    client.post(f"/admin/customers/{c.id}/panel-admins/add",
                data={"username": "newadmin", "password": "Sup3rSecret", "role_key": "admin"})
    assert "password_hash" in _by_username(_directives(lic), "newadmin")
    # the radius reports its admin inventory back — 'newadmin' now exists there.
    import_radius_admins(c, lic, [
        {"id": 1, "username": "root", "is_primary": True, "enabled": True},
        {"id": 7, "username": "newadmin", "role": "operator", "enabled": True},
    ])
    db.session.commit()
    db.session.expire_all()
    row = CustomerManagedAdmin.query.filter_by(customer_id=c.id, username="newadmin").one()
    assert row.password_provisioned is True and row.password_hash == ""
    d = _by_username(_directives(lic), "newadmin")
    assert d["op"] == "upsert" and "password_hash" not in d   # idempotent, no secret


# ── all management actions are super-admin gated ─────────────────────────────
def test_actions_require_super_admin(app, client, cust_lic):
    c, _lic = cust_lic
    # logged in as a NON-super admin.
    non_super = Admin(username="op1", password_hash="x", full_name="Op", is_super_admin=False, active=True)
    db.session.add(non_super)
    db.session.commit()
    with client.session_transaction() as s:
        s["admin_id"] = non_super.id
    r = client.post(f"/admin/customers/{c.id}/panel-admins/add",
                    data={"username": "x", "password": "Sup3rSecret", "role_key": "admin"},
                    follow_redirects=False)
    assert r.status_code in (302, 403)
    assert CustomerManagedAdmin.query.filter_by(customer_id=c.id, username="x").first() is None
