from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import inspect
from sqlalchemy.exc import IntegrityError

from app.extensions import db
from app.models import Customer, License, Plan, utcnow


def table_indexes(table_name: str) -> set[str]:
    return {item["name"] for item in inspect(db.engine).get_indexes(table_name)}


def test_production_query_indexes_exist(app):
    assert {
        "ix_licenses_status_expires_at",
        "ix_licenses_expires_at",
        "ix_licenses_created_at",
    }.issubset(table_indexes("licenses"))
    assert {
        "ix_license_checks_license_checked_at",
        "ix_license_checks_result_checked_at",
        "ix_license_checks_license_ip",
    }.issubset(table_indexes("license_checks"))
    assert {
        "ix_renewals_customer_created_at",
        "ix_renewals_license_created_at",
    }.issubset(table_indexes("renewals"))
    assert {
        "ix_audit_logs_entity_created_at",
        "ix_audit_logs_action_created_at",
    }.issubset(table_indexes("audit_logs"))


def test_plan_slug_unique_constraint_is_enforced(app):
    db.session.add(Plan(name="Duplicate Starter", slug="starter", monthly_price=10))

    with pytest.raises(IntegrityError):
        db.session.commit()

    db.session.rollback()


def test_license_key_unique_constraint_is_enforced(app):
    customer = Customer(company_name="Constraint Customer")
    plan = Plan.query.filter_by(slug="pro").first()
    db.session.add(customer)
    db.session.flush()

    now = utcnow()
    key = "HBR-2026-UNIQ-TEST-0001"
    db.session.add_all([
        License(
            customer_id=customer.id,
            plan_id=plan.id,
            license_key=key,
            expires_at=now + timedelta(days=30),
        ),
        License(
            customer_id=customer.id,
            plan_id=plan.id,
            license_key=key,
            expires_at=now + timedelta(days=60),
        ),
    ])

    with pytest.raises(IntegrityError):
        db.session.commit()

    db.session.rollback()
