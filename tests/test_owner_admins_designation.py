"""Provider-side OWNER-admin designation — feat/owner-admins-designation.

The owner of a customer's radius panel is designated EXPLICITLY from the
licensing panel (here), on the customer detail page, by a STABLE key (admin
username OR email — never the panel-local numeric id). MULTIPLE owners are
supported (e.g. two partner co-owners). The designation rides the existing
license/runtime sync as the contract key ``owner_admins`` (a list of keys),
which the customer panel consumes to mark the matching admins as owners
(full RBAC bypass + uncapped) and replaces its min-id owner heuristic.

This module proves the PROVIDER side:
  • default = no designation → owner_admins is an empty list in the contract.
  • the provider route sets 1 owner, then 2 owners; both rides the contract.
  • an empty submit is rejected (≥1 required); clear reverts to no designation.
  • the key flows through BOTH the runtime-contract and the identity-sync payload.
"""
from __future__ import annotations

from datetime import timedelta

import pytest

from app.extensions import db
from app.models import Admin, Customer, License, Plan, utcnow
from app.services.customer_control import (
    build_identity_sync_contract,
    build_runtime_contract_for_license,
    normalize_owner_admins,
)


@pytest.fixture()
def cust_lic(app):
    plan = Plan.query.filter_by(slug="pro").one()
    c = Customer(company_name="Owner Co", email="owner@example.com", status="active")
    db.session.add(c)
    db.session.flush()
    lic = License(customer_id=c.id, plan_id=plan.id, license_key="LIC-OWNER-TEST",
                  status="active", starts_at=utcnow() - timedelta(days=1),
                  expires_at=utcnow() + timedelta(days=365),
                  grace_until=utcnow() + timedelta(days=372))
    db.session.add(lic)
    db.session.commit()
    return c, lic


def _admin_client(app, client):
    admin = Admin.query.first()
    with client.session_transaction() as s:
        s["admin_id"] = admin.id
    return client


def _owner_admins(lic):
    return build_runtime_contract_for_license(
        lic, license_active=True, status="active")["owner_admins"]


# ── default: no designation → empty list ─────────────────────────────────────
def test_owner_admins_empty_by_default(cust_lic):
    _c, lic = cust_lic
    assert _owner_admins(lic) == []


# ── set ONE owner via the provider route ─────────────────────────────────────
def test_set_one_owner(app, client, cust_lic):
    c, lic = cust_lic
    _admin_client(app, client)
    r = client.post(f"/admin/customers/{c.id}/owner-admins",
                    data={"action": "save", "owner_admins": "alice"},
                    follow_redirects=False)
    assert r.status_code in (301, 302)
    db.session.expire_all()
    assert _owner_admins(lic) == ["alice"]
    assert db.session.get(Customer, c.id).owner_admins == ["alice"]


# ── set TWO owners (partners) — both ride the contract ───────────────────────
def test_set_two_owners(app, client, cust_lic):
    c, lic = cust_lic
    _admin_client(app, client)
    # mixed entry: newline + comma + a quick-add checkbox key, with a dupe.
    r = client.post(f"/admin/customers/{c.id}/owner-admins", data={
        "action": "save",
        "owner_admins": "alice\nbob@example.com, alice",
        "owner_admin_key": "bob@example.com",
    }, follow_redirects=False)
    assert r.status_code in (301, 302)
    db.session.expire_all()
    owners = _owner_admins(lic)
    assert owners == ["alice", "bob@example.com"]      # de-duped, order-preserved
    # rides the identity-sync payload too (same key, same source).
    idc = build_identity_sync_contract(lic, license_active=True, status="active")
    assert idc["owner_admins"] == ["alice", "bob@example.com"]


# ── empty submit rejected; ≥1 owner required ─────────────────────────────────
def test_empty_submit_rejected(app, client, cust_lic):
    c, lic = cust_lic
    _admin_client(app, client)
    client.post(f"/admin/customers/{c.id}/owner-admins",
                data={"action": "save", "owner_admins": "owner"},
                follow_redirects=False)
    db.session.expire_all()
    assert _owner_admins(lic) == ["owner"]
    # blank submit must NOT wipe the existing designation.
    client.post(f"/admin/customers/{c.id}/owner-admins",
                data={"action": "save", "owner_admins": "   \n , "},
                follow_redirects=False)
    db.session.expire_all()
    assert _owner_admins(lic) == ["owner"]


# ── explicit clear reverts to no designation (panel falls back to min-id) ─────
def test_clear_reverts(app, client, cust_lic):
    c, lic = cust_lic
    _admin_client(app, client)
    client.post(f"/admin/customers/{c.id}/owner-admins",
                data={"action": "save", "owner_admins": "alice\nbob"},
                follow_redirects=False)
    db.session.expire_all()
    assert len(_owner_admins(lic)) == 2
    client.post(f"/admin/customers/{c.id}/owner-admins",
                data={"action": "clear"}, follow_redirects=False)
    db.session.expire_all()
    assert _owner_admins(lic) == []


# ── normalizer unit: trim, drop blanks, case-insensitive de-dupe ─────────────
def test_normalize_owner_admins():
    assert normalize_owner_admins([" alice ", "ALICE", "", "bob@x.com", "bob@x.com"]) == [
        "alice", "bob@x.com"]
    assert normalize_owner_admins(None) == []
    assert normalize_owner_admins("notalist") == []
