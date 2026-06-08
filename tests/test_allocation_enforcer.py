"""اختبارات allocation_enforcer — PART 2B Production Hardening.

تغطّي:
  1. dry-run: لا يكتب في DB، يُعيد العدد الصحيح
  2. apply: يُعيَّر التخصيصات المنتهية → status='expired'
  3. apply: يُنشئ AuditLog مرة واحدة لكل تخصيص
  4. idempotency: التخصيصات المنتهية فعلاً لا تُعالَج مرة أخرى
  5. --customer-id: نطاق محدود لعميل واحد
  6. تخصيص لم ينتهِ بعد يبقى active
"""
from __future__ import annotations

import pytest
from datetime import datetime, timezone, timedelta


# ══════════════════════════════════════════════════════════════════

@pytest.fixture()
def app():
    """نفس fixture المستخدمة في بقية الاختبارات (من conftest.py)."""
    from app import create_app, seed_defaults
    from app.config import TestingConfig
    from app.extensions import db

    application = create_app(TestingConfig)
    with application.app_context():
        db.create_all()
        seed_defaults(application)
        yield application
        db.session.remove()
        db.drop_all()


def _utc_past(days: int = 1) -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=days)


def _utc_future(days: int = 30) -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(days=days)


_CUSTOMER_SEQ = [0]


def _make_customer(app):
    from app.extensions import db
    from app.models import Customer
    _CUSTOMER_SEQ[0] += 1
    n = _CUSTOMER_SEQ[0]
    c = Customer(
        company_name=f"Test ISP {n}",
        contact_name=f"Admin {n}",
        email=f"isp{n}@test.com",
        status="active",
        runtime_url="http://localhost:5000",
    )
    db.session.add(c)
    db.session.flush()
    return c


def _make_allocation(customer_id: int, expires_at, status: str = "active"):
    from app.extensions import db
    from app.models import ServiceAllocation
    a = ServiceAllocation(
        customer_id=customer_id,
        service_type="pptp_vpn",
        status=status,
        expires_at=expires_at,
        max_accounts=10,
        speed_limit_mbps=100,
    )
    db.session.add(a)
    db.session.flush()
    return a


# ═══════════════════════════════════════════════════════════════════

class TestAllocationEnforcerDryRun:

    def test_dry_run_counts_but_does_not_write(self, app):
        from app.extensions import db
        with app.app_context():
            c = _make_customer(app)
            alloc = _make_allocation(c.id, _utc_past(5))
            db.session.commit()
            alloc_id = alloc.id

            from app.services.allocation_enforcer import run
            result = run(dry_run=True)

        assert result["allocations_expired"] >= 1
        assert result["dry_run"] is True

        # DB must not have changed
        with app.app_context():
            from app.models import ServiceAllocation
            a = ServiceAllocation.query.get(alloc_id)
            assert a.status == "active", "dry-run must NOT change allocation status"

    def test_dry_run_no_audit_log(self, app):
        from app.extensions import db
        with app.app_context():
            c = _make_customer(app)
            _make_allocation(c.id, _utc_past(2))
            db.session.commit()

            from app.models import AuditLog
            before = AuditLog.query.count()

            from app.services.allocation_enforcer import run
            run(dry_run=True)

            after = AuditLog.query.count()
            assert after == before, "dry-run must NOT write audit log"


class TestAllocationEnforcerApply:

    def test_apply_expires_allocation(self, app):
        from app.extensions import db
        with app.app_context():
            c = _make_customer(app)
            alloc = _make_allocation(c.id, _utc_past(3))
            db.session.commit()
            alloc_id = alloc.id

            from app.services.allocation_enforcer import run
            result = run(dry_run=False)

        assert result["allocations_expired"] >= 1
        assert result.get("errors", 0) == 0

        with app.app_context():
            from app.models import ServiceAllocation
            a = ServiceAllocation.query.get(alloc_id)
            assert a.status == "expired"

    def test_apply_creates_audit_log_once(self, app):
        from app.extensions import db
        with app.app_context():
            c = _make_customer(app)
            alloc = _make_allocation(c.id, _utc_past(1))
            db.session.commit()
            alloc_id = alloc.id

            from app.models import AuditLog
            from app.services.allocation_enforcer import run
            run(dry_run=False)

            logs = AuditLog.query.filter_by(
                entity_type="service_allocation",
                entity_id=alloc_id,
                action="expire",
            ).all()
            assert len(logs) == 1

    def test_non_expired_stays_active(self, app):
        from app.extensions import db
        with app.app_context():
            c = _make_customer(app)
            alloc = _make_allocation(c.id, _utc_future(30))
            db.session.commit()
            alloc_id = alloc.id

            from app.services.allocation_enforcer import run
            result = run(dry_run=False)

        assert result["allocations_expired"] == 0

        with app.app_context():
            from app.models import ServiceAllocation
            a = ServiceAllocation.query.get(alloc_id)
            assert a.status == "active"

    def test_already_expired_is_idempotent(self, app):
        from app.extensions import db
        with app.app_context():
            c = _make_customer(app)
            alloc = _make_allocation(c.id, _utc_past(10), status="expired")
            db.session.commit()

            from app.services.allocation_enforcer import run
            r1 = run(dry_run=False)
            r2 = run(dry_run=False)

        assert r1["allocations_expired"] == 0
        assert r2["allocations_expired"] == 0


class TestAllocationEnforcerCustomerScope:

    def test_customer_id_scope_limits_to_one_customer(self, app):
        from app.extensions import db
        c1_id = None
        c2_id = None
        a1_id = None
        a2_id = None

        with app.app_context():
            c1 = _make_customer(app)
            c2 = _make_customer(app)
            db.session.flush()
            c1_id = c1.id
            c2_id = c2.id

            a1 = _make_allocation(c1_id, _utc_past(1))
            a2 = _make_allocation(c2_id, _utc_past(1))
            db.session.commit()
            a1_id = a1.id
            a2_id = a2.id

            from app.services.allocation_enforcer import run
            result = run(dry_run=False, customer_id=c1_id)

        assert result["allocations_expired"] == 1
        assert result["customer_id"] == c1_id

        with app.app_context():
            from app.models import ServiceAllocation
            assert ServiceAllocation.query.get(a1_id).status == "expired"
            assert ServiceAllocation.query.get(a2_id).status == "active", \
                "other customer alloc must be untouched"

    def test_customer_id_dry_run_scope(self, app):
        from app.extensions import db
        with app.app_context():
            c1 = _make_customer(app)
            _make_allocation(c1.id, _utc_past(1))
            db.session.commit()

            from app.services.allocation_enforcer import run
            result = run(dry_run=True, customer_id=c1.id)

        assert result["allocations_expired"] >= 1
        assert result["dry_run"] is True
        assert result["customer_id"] == c1.id
