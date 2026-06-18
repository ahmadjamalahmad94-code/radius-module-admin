"""Customer self-service portal («بوابة العميل») — /portal dashboard.

Verifies the polished self-service views: license (status/package/countdown +
renew→pricing CTA), team (users/admins + plan admin limit), and the services
gate (free available, paid «طلب تفعيل», hidden omitted, «الجهات» granted-only).
"""
from __future__ import annotations

from datetime import timedelta

import pytest

from app.extensions import db
from app.models import Customer, CustomerUser, License, Plan, utcnow
from app.services.customer_control import get_or_create_service_entitlement


def _make(plan_slug="pkg_networks", *, expires_days=200, status="active"):
    plan = Plan.query.filter_by(slug=plan_slug).one()
    c = Customer(company_name="Portal Co", email="portal@x.com", status="active")
    db.session.add(c)
    db.session.flush()
    u = CustomerUser(customer_id=c.id, username="powner", email="portal@x.com",
                     role_key="owner", active=True)
    u.set_password("ownerpass12345", increment_version=False)
    u.password_version = 1
    db.session.add(u)
    lic = License(customer_id=c.id, plan_id=plan.id, license_key="LK-PORTAL-T",
                  status=status, starts_at=utcnow() - timedelta(days=1),
                  expires_at=utcnow() + timedelta(days=expires_days),
                  grace_until=utcnow() + timedelta(days=expires_days + 7))
    db.session.add(lic)
    db.session.commit()
    return c, u, lic


def _portal(app, client, **kw):
    with app.app_context():
        c, u, lic = _make(**kw)
        cid, uid = c.id, u.id
    with client.session_transaction() as s:
        s["customer_user_id"] = uid
        s["customer_id"] = cid
        s["customer_name"] = "powner"
    r = client.get("/portal")
    assert r.status_code == 200
    return r.get_data(as_text=True), cid


# ── new views present ─────────────────────────────────────────────────────────
def test_portal_has_license_and_team_views(app, client):
    body, _ = _portal(app, client)
    assert 'data-pp-view="license"' in body and 'data-pp-pane="license"' in body
    assert 'data-pp-view="team"' in body and 'data-pp-pane="team"' in body
    assert "ترخيصي والباقة" in body
    assert "المستخدمون والمدراء" in body


def test_license_view_shows_package_countdown_and_renew(app, client):
    body, _ = _portal(app, client, plan_slug="pkg_networks", expires_days=200)
    assert "حزمة الشبكات" in body                      # package name
    assert "المتبقّي على الترخيص" in body              # countdown KPI
    assert "اعرض الباقات" in body                       # renew CTA
    assert "/pricing" in body                          # → landing pricing


def test_team_view_lists_user_and_admin_limit(app, client):
    body, _ = _portal(app, client)
    assert "powner" in body                            # the customer's user
    assert "حدّ المدراء في الباقة" in body             # plan admin limit label


# ── renew prompt on expiry/grace ──────────────────────────────────────────────
def test_renew_banner_when_expiring_soon(app, client):
    body, _ = _portal(app, client, expires_days=5)     # ≤14 days
    assert "اعرض الباقات وجدّد" in body


def test_renew_banner_when_in_grace(app, client):
    body, _ = _portal(app, client, status="grace", expires_days=-2)
    assert "اعرض الباقات وجدّد" in body


# ── services gate correctness ─────────────────────────────────────────────────
def test_services_gate_paid_shows_activation_free_available(app, client):
    body, _ = _portal(app, client)
    # a paid service is a visible upsell with «طلب تفعيل»
    assert "طلب تفعيل" in body
    # free software shows «ضمن خطتك»
    assert "ضمن خطتك" in body


def test_entities_hidden_until_granted_in_portal(app, client):
    """«الجهات» (multi_tenant) is fully hidden in the portal until granted."""
    with app.app_context():
        c, u, lic = _make()
        cid, uid = c.id, u.id
    with client.session_transaction() as s:
        s["customer_user_id"] = uid; s["customer_id"] = cid; s["customer_name"] = "powner"
    body = client.get("/portal").get_data(as_text=True)
    # the service card emits the service_key in data-name; absent while hidden
    assert "multi_tenant" not in body                  # not shown while hidden
    assert "المستأجرون" not in body
    # grant it → now visible
    with app.app_context():
        c = db.session.get(Customer, cid)
        ent = get_or_create_service_entitlement(c, "multi_tenant")
        ent.enabled = True
        ent.status = "active"
        ent.config = {"tier": "paid", "visibility": "granted",
                      "entity_count": 3, "per_entity_limits": {"max_subscribers": 100}}
        db.session.commit()
    body2 = client.get("/portal").get_data(as_text=True)
    assert "multi_tenant" in body2                      # shown once granted
    assert "المستأجرون" in body2
