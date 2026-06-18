"""«إخفاء للترتيب» (declutter-hide) vs «موقوفة» (commercial block).

The owner uses HIDE to declutter a customer's panel — remove services that
customer doesn't need so their view is clean. It is NOT a commercial block:
fully reversible, no 403, the service keeps working. This is DISTINCT from a
«موقوفة» suspend, which is the commercial hard-block (gate "disabled" → hide+403).

These two provider controls are orthogonal; this suite locks that they emit
DIFFERENT contract states so the radius never conflates them.
"""
from __future__ import annotations

from datetime import timedelta

import pytest

from app.extensions import db
from app.models import Customer, License, Plan, utcnow
from app.services.customer_control import (
    build_runtime_contract_for_license,
    get_or_create_service_entitlement,
    set_service_hidden,
)


@pytest.fixture()
def cust_lic(app):
    plan = Plan.query.filter_by(slug="pro").one()
    c = Customer(company_name="Hide Co", email="hide@example.com", status="active")
    db.session.add(c)
    db.session.flush()
    lic = License(customer_id=c.id, plan_id=plan.id, license_key="LIC-HIDE-TEST",
                  status="active", starts_at=utcnow() - timedelta(days=1),
                  expires_at=utcnow() + timedelta(days=365),
                  grace_until=utcnow() + timedelta(days=372))
    db.session.add(lic)
    db.session.commit()
    return c, lic


def _svc(lic, key):
    return build_runtime_contract_for_license(
        lic, license_active=True, status="active")["services"][key]


def _grant(lic, gate):
    return build_runtime_contract_for_license(
        lic, license_active=True, status="active")["provider_grants"].get(gate)


# ── declutter-hide: visible-removal WITHOUT a commercial block ────────────────
def test_declutter_hide_keeps_service_working(cust_lic):
    c, lic = cust_lic
    ent = get_or_create_service_entitlement(c, "reports")
    ent.status = "active"
    ent.enabled = True
    set_service_hidden(ent, True)
    db.session.commit()
    svc = _svc(lic, "reports")
    assert svc["hidden"] is True          # removed from nav for tidiness
    assert svc["enabled"] is True         # …but still ENABLED — no 403
    assert svc["status"] != "suspended"
    # the gate mirrors: hidden, yet enabled + active (NOT disabled)
    g = _grant(lic, "reports")
    assert g["hidden"] is True
    assert g["enabled"] is True
    assert g["status"] == "active"        # distinctly NOT "disabled"


def test_declutter_hide_is_reversible(cust_lic):
    c, lic = cust_lic
    ent = get_or_create_service_entitlement(c, "reports")
    ent.status = "active"
    ent.enabled = True
    set_service_hidden(ent, True)
    db.session.commit()
    assert _svc(lic, "reports")["hidden"] is True
    # un-hide → back in the nav, nothing else changed
    set_service_hidden(ent, False)
    db.session.commit()
    svc = _svc(lic, "reports")
    assert svc["hidden"] is False
    assert svc["enabled"] is True


# ── commercial block: the OTHER state ─────────────────────────────────────────
def test_commercial_block_is_disabled_403(cust_lic):
    c, lic = cust_lic
    ent = get_or_create_service_entitlement(c, "reports")
    ent.status = "suspended"
    ent.enabled = False
    db.session.commit()
    g = _grant(lic, "reports")
    assert g["status"] == "disabled"      # hard block → radius hide + 403
    assert g["enabled"] is False


# ── orthogonal: hide and suspend are independent ──────────────────────────────
def test_hide_and_suspend_are_independent(cust_lic):
    c, lic = cust_lic
    ent = get_or_create_service_entitlement(c, "reports")
    # commercial block AND declutter-hidden at once
    ent.status = "suspended"
    ent.enabled = False
    set_service_hidden(ent, True)
    db.session.commit()
    g = _grant(lic, "reports")
    assert g["status"] == "disabled" and g["hidden"] is True
    # lifting ONLY the commercial block (resume) leaves it still decluttered
    ent.status = "active"
    ent.enabled = True
    db.session.commit()
    g = _grant(lic, "reports")
    assert g["status"] == "active"        # commercial block gone
    assert g["hidden"] is True            # still hidden-for-tidiness
