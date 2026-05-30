from __future__ import annotations

import json
from datetime import datetime, timezone

from werkzeug.security import check_password_hash, generate_password_hash

from .extensions import db


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def json_loads(raw: str | None, default):
    if not raw:
        return default
    try:
        return json.loads(raw)
    except (TypeError, ValueError):
        return default


def json_dumps(value) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


class TimestampMixin:
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=utcnow, onupdate=utcnow, nullable=False)


class Admin(TimestampMixin, db.Model):
    __tablename__ = "admins"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    full_name = db.Column(db.String(160), default="", nullable=False)
    email = db.Column(db.String(160), default="", nullable=False)
    active = db.Column(db.Boolean, default=True, nullable=False)
    last_login_at = db.Column(db.DateTime)

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)


class Customer(TimestampMixin, db.Model):
    __tablename__ = "customers"
    __table_args__ = (
        db.Index("ix_customers_status_created_at", "status", "created_at"),
    )

    id = db.Column(db.Integer, primary_key=True)
    company_name = db.Column(db.String(180), nullable=False, index=True)
    contact_name = db.Column(db.String(160), default="", nullable=False)
    email = db.Column(db.String(180), default="", nullable=False)
    phone = db.Column(db.String(80), default="", nullable=False)
    country = db.Column(db.String(100), default="", nullable=False)
    city = db.Column(db.String(100), default="", nullable=False)
    runtime_url = db.Column(db.String(255), default="", nullable=False)
    notes = db.Column(db.Text, default="", nullable=False)
    status = db.Column(db.String(20), default="active", nullable=False, index=True)

    licenses = db.relationship("License", back_populates="customer", lazy="dynamic")
    renewals = db.relationship("Renewal", back_populates="customer", lazy="dynamic")
    vpn_entitlement = db.relationship("CustomerVpnEntitlement", back_populates="customer", uselist=False)
    users = db.relationship("CustomerUser", back_populates="customer", lazy="dynamic")
    service_entitlements = db.relationship("CustomerServiceEntitlement", back_populates="customer", lazy="dynamic")
    service_requests = db.relationship("CustomerServiceRequest", back_populates="customer", lazy="dynamic")


class CustomerUser(TimestampMixin, db.Model):
    __tablename__ = "customer_users"
    __table_args__ = (
        db.UniqueConstraint("customer_id", "username", name="uq_customer_users_customer_username"),
        db.Index("ix_customer_users_customer_active", "customer_id", "active"),
        db.Index("ix_customer_users_username", "username"),
    )

    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey("customers.id"), nullable=False, index=True)
    username = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(180), default="", nullable=False, index=True)
    full_name = db.Column(db.String(160), default="", nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    password_hash_scheme = db.Column(db.String(40), default="werkzeug", nullable=False)
    password_version = db.Column(db.Integer, default=1, nullable=False)
    role_key = db.Column(db.String(40), default="owner", nullable=False, index=True)
    active = db.Column(db.Boolean, default=True, nullable=False, index=True)
    last_password_changed_at = db.Column(db.DateTime, default=utcnow, nullable=False)

    customer = db.relationship("Customer", back_populates="users")

    def set_password(self, password: str, *, increment_version: bool = True) -> None:
        self.password_hash = generate_password_hash(password)
        self.password_hash_scheme = "werkzeug"
        self.last_password_changed_at = utcnow()
        if increment_version:
            self.password_version = int(self.password_version or 0) + 1

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)


class ServiceCatalogItem(TimestampMixin, db.Model):
    __tablename__ = "service_catalog_items"
    __table_args__ = (
        db.Index("ix_service_catalog_status_sort", "status", "sort_order"),
    )

    id = db.Column(db.Integer, primary_key=True)
    service_key = db.Column(db.String(80), unique=True, nullable=False, index=True)
    title = db.Column(db.String(180), default="", nullable=False)
    short_description = db.Column(db.String(500), default="", nullable=False)
    details = db.Column(db.Text, default="", nullable=False)
    category = db.Column(db.String(80), default="core", nullable=False, index=True)
    price = db.Column(db.Numeric(12, 2), default=0, nullable=False)
    currency = db.Column(db.String(12), default="USD", nullable=False)
    billing_mode = db.Column(db.String(40), default="monthly", nullable=False)
    requires_payment = db.Column(db.Boolean, default=False, nullable=False)
    requires_admin_approval = db.Column(db.Boolean, default=True, nullable=False)
    activation_mode = db.Column(db.String(60), default="manual", nullable=False)
    command_key = db.Column(db.String(100), default="", nullable=False)
    status = db.Column(db.String(30), default="active", nullable=False, index=True)
    sort_order = db.Column(db.Integer, default=100, nullable=False)
    metadata_json = db.Column(db.Text, default="{}", nullable=False)

    entitlements = db.relationship("CustomerServiceEntitlement", back_populates="catalog_item", lazy="dynamic")

    @property
    def catalog_metadata(self) -> dict:
        return json_loads(self.metadata_json, {})

    @catalog_metadata.setter
    def catalog_metadata(self, value: dict) -> None:
        self.metadata_json = json_dumps(value or {})

    def _set_metadata_value(self, key: str, value) -> None:
        data = self.catalog_metadata
        data[key] = value
        self.catalog_metadata = data

    @property
    def name(self) -> str:
        return str(self.catalog_metadata.get("name") or self.title or "")

    @name.setter
    def name(self, value: str) -> None:
        text = str(value or "").strip()
        self._set_metadata_value("name", text)
        if not self.title:
            self.title = text

    @property
    def name_ar(self) -> str:
        return str(self.catalog_metadata.get("name_ar") or self.title or "")

    @name_ar.setter
    def name_ar(self, value: str) -> None:
        text = str(value or "").strip()
        self._set_metadata_value("name_ar", text)
        if text:
            self.title = text

    @property
    def description(self) -> str:
        return self.short_description or self.details or ""

    @description.setter
    def description(self, value: str) -> None:
        text = str(value or "").strip()
        self.short_description = text[:500]
        self.details = text

    @property
    def default_enabled(self) -> bool:
        return bool(self.catalog_metadata.get("default_enabled", False))

    @default_enabled.setter
    def default_enabled(self, value: bool) -> None:
        self._set_metadata_value("default_enabled", bool(value))

    @property
    def is_active(self) -> bool:
        return self.status == "active"

    @is_active.setter
    def is_active(self, value: bool) -> None:
        self.status = "active" if value else "inactive"

    @property
    def price_monthly(self):
        return self.price

    @price_monthly.setter
    def price_monthly(self, value) -> None:
        self.price = value or 0


class CustomerServiceEntitlement(TimestampMixin, db.Model):
    __tablename__ = "customer_service_entitlements"
    __table_args__ = (
        db.UniqueConstraint("customer_id", "service_key", name="uq_customer_service_entitlements_customer_service"),
        db.Index("ix_customer_service_entitlements_customer_status", "customer_id", "status"),
    )

    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey("customers.id"), nullable=False, index=True)
    license_id = db.Column(db.Integer, db.ForeignKey("licenses.id"), nullable=True, index=True)
    service_key = db.Column(db.String(80), db.ForeignKey("service_catalog_items.service_key"), nullable=False, index=True)
    enabled = db.Column(db.Boolean, default=False, nullable=False, index=True)
    status = db.Column(db.String(20), default="disabled", nullable=False, index=True)
    plan_code = db.Column(db.String(80), default="", nullable=False)
    limits_json = db.Column(db.Text, default="{}", nullable=False)
    config_json = db.Column(db.Text, default="{}", nullable=False)
    price_monthly = db.Column(db.Numeric(10, 2), nullable=True)
    expires_at = db.Column(db.DateTime, nullable=True)
    notes = db.Column(db.Text, default="", nullable=False)
    updated_by_admin_id = db.Column(db.Integer, db.ForeignKey("admins.id"), nullable=True)

    customer = db.relationship("Customer", back_populates="service_entitlements")
    license = db.relationship("License")
    catalog_item = db.relationship("ServiceCatalogItem", back_populates="entitlements")
    updated_by = db.relationship("Admin")

    @property
    def limits(self) -> dict:
        return json_loads(self.limits_json, {})

    @limits.setter
    def limits(self, value: dict) -> None:
        self.limits_json = json_dumps(value or {})

    @property
    def config(self) -> dict:
        return json_loads(self.config_json, {})

    @config.setter
    def config(self, value: dict) -> None:
        self.config_json = json_dumps(value or {})


class CustomerServiceRequest(TimestampMixin, db.Model):
    __tablename__ = "customer_service_requests"
    __table_args__ = (
        db.Index("ix_customer_service_requests_customer_status", "customer_id", "status"),
        db.Index("ix_customer_service_requests_service_status", "service_key", "status"),
    )

    id = db.Column(db.Integer, primary_key=True)
    public_reference = db.Column(db.String(40), default="", nullable=False)
    customer_id = db.Column(db.Integer, db.ForeignKey("customers.id"), nullable=False, index=True)
    license_id = db.Column(db.Integer, db.ForeignKey("licenses.id"), nullable=True, index=True)
    service_id = db.Column(db.Integer, nullable=True)
    payment_request_id = db.Column(db.Integer, db.ForeignKey("license_payment_requests.id"), nullable=True, index=True)
    requested_by_access_id = db.Column(db.Integer, nullable=True)
    requested_by_admin_id = db.Column(db.Integer, db.ForeignKey("admins.id"), nullable=True, index=True)
    approved_by_admin_id = db.Column(db.Integer, db.ForeignKey("admins.id"), nullable=True, index=True)
    activated_by_admin_id = db.Column(db.Integer, db.ForeignKey("admins.id"), nullable=True, index=True)
    service_key = db.Column(db.String(80), db.ForeignKey("service_catalog_items.service_key"), nullable=False, index=True)
    title = db.Column(db.String(180), default="", nullable=False)
    status = db.Column(db.String(40), default="pending", nullable=False, index=True)
    payment_status = db.Column(db.String(40), default="not_required", nullable=False)
    amount = db.Column(db.Numeric(12, 2), default=0, nullable=False)
    currency = db.Column(db.String(12), default="USD", nullable=False)
    customer_note = db.Column(db.Text, default="", nullable=False)
    admin_note = db.Column(db.Text, default="", nullable=False)
    requested_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    approved_at = db.Column(db.DateTime, nullable=True)
    activated_at = db.Column(db.DateTime, nullable=True)
    completed_at = db.Column(db.DateTime, nullable=True)
    rejected_at = db.Column(db.DateTime, nullable=True)
    config_json = db.Column(db.Text, default="{}", nullable=False)
    metadata_json = db.Column(db.Text, default="{}", nullable=False)

    customer = db.relationship("Customer", back_populates="service_requests")
    catalog_item = db.relationship("ServiceCatalogItem")
    license = db.relationship("License")
    payment_request = db.relationship("LicensePaymentRequest")
    requested_by_admin = db.relationship("Admin", foreign_keys=[requested_by_admin_id])
    approved_by_admin = db.relationship("Admin", foreign_keys=[approved_by_admin_id])
    activated_by_admin = db.relationship("Admin", foreign_keys=[activated_by_admin_id])

    @property
    def request_metadata(self) -> dict:
        return json_loads(self.metadata_json, {})

    @request_metadata.setter
    def request_metadata(self, value: dict) -> None:
        self.metadata_json = json_dumps(value or {})

    def _set_metadata_value(self, key: str, value) -> None:
        data = self.request_metadata
        data[key] = value
        self.request_metadata = data

    @property
    def customer_user_id(self) -> int | None:
        value = self.request_metadata.get("customer_user_id")
        return int(value) if value not in (None, "") else None

    @customer_user_id.setter
    def customer_user_id(self, value: int | None) -> None:
        self._set_metadata_value("customer_user_id", value)

    @property
    def request_type(self) -> str:
        return str(self.request_metadata.get("request_type") or "activation")

    @request_type.setter
    def request_type(self, value: str) -> None:
        self._set_metadata_value("request_type", str(value or "activation").strip()[:40])

    @property
    def notes(self) -> str:
        return self.customer_note

    @notes.setter
    def notes(self, value: str) -> None:
        self.customer_note = str(value or "")

    @property
    def desired_limits(self) -> dict:
        return json_loads(self.config_json, {})

    @desired_limits.setter
    def desired_limits(self, value: dict) -> None:
        self.config_json = json_dumps(value or {})


class Plan(TimestampMixin, db.Model):
    __tablename__ = "plans"
    __table_args__ = (
        db.Index("ix_plans_status_name", "status", "name"),
    )

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    slug = db.Column(db.String(120), unique=True, nullable=False, index=True)
    monthly_price = db.Column(db.Numeric(10, 2), default=0, nullable=False)
    currency = db.Column(db.String(12), default="USD", nullable=False)
    max_users = db.Column(db.Integer, default=100, nullable=False)
    max_nas = db.Column(db.Integer, default=1, nullable=False)
    max_admins = db.Column(db.Integer, default=1, nullable=False)
    max_devices = db.Column(db.Integer, default=1, nullable=False)
    features_json = db.Column(db.Text, default="{}", nullable=False)
    status = db.Column(db.String(20), default="active", nullable=False, index=True)

    licenses = db.relationship("License", back_populates="plan", lazy="dynamic")

    @property
    def features(self) -> dict:
        return json_loads(self.features_json, {})

    @features.setter
    def features(self, value: dict) -> None:
        self.features_json = json_dumps(value or {})

    def public_dict(self) -> dict:
        return {
            "name": self.name,
            "max_users": self.max_users,
            "max_nas": self.max_nas,
            "max_admins": self.max_admins,
        }


class VpnServicePlan(TimestampMixin, db.Model):
    __tablename__ = "vpn_service_plans"
    __table_args__ = (
        db.Index("ix_vpn_service_plans_active_code", "is_active", "code"),
    )

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(140), nullable=False)
    code = db.Column(db.String(80), unique=True, nullable=False, index=True)
    description = db.Column(db.Text, default="", nullable=False)
    download_mbps = db.Column(db.Integer, nullable=False)
    upload_mbps = db.Column(db.Integer, nullable=False)
    max_vpn_users = db.Column(db.Integer, nullable=False)
    max_locations = db.Column(db.Integer, default=1, nullable=False)
    traffic_quota_gb = db.Column(db.Integer, nullable=True)
    price_monthly = db.Column(db.Numeric(10, 2), nullable=True)
    is_active = db.Column(db.Boolean, default=True, nullable=False, index=True)

    entitlements = db.relationship("CustomerVpnEntitlement", back_populates="vpn_plan", lazy="dynamic")


class CustomerVpnEntitlement(TimestampMixin, db.Model):
    __tablename__ = "customer_vpn_entitlements"
    __table_args__ = (
        db.UniqueConstraint("customer_id", name="uq_customer_vpn_entitlements_customer"),
        db.Index("ix_customer_vpn_entitlements_customer_status", "customer_id", "status"),
    )

    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey("customers.id"), nullable=False, index=True)
    license_id = db.Column(db.Integer, db.ForeignKey("licenses.id"), nullable=True, index=True)
    vpn_plan_id = db.Column(db.Integer, db.ForeignKey("vpn_service_plans.id"), nullable=True, index=True)
    enabled = db.Column(db.Boolean, default=False, nullable=False, index=True)
    status = db.Column(db.String(20), default="disabled", nullable=False, index=True)
    download_mbps = db.Column(db.Integer, nullable=True)
    upload_mbps = db.Column(db.Integer, nullable=True)
    max_vpn_users = db.Column(db.Integer, nullable=True)
    max_locations = db.Column(db.Integer, default=1, nullable=True)
    expires_at = db.Column(db.DateTime, nullable=True)
    notes = db.Column(db.Text, default="", nullable=False)
    updated_by_admin_id = db.Column(db.Integer, db.ForeignKey("admins.id"), nullable=True)

    customer = db.relationship("Customer", back_populates="vpn_entitlement")
    license = db.relationship("License")
    vpn_plan = db.relationship("VpnServicePlan", back_populates="entitlements")
    updated_by = db.relationship("Admin")


class License(TimestampMixin, db.Model):
    __tablename__ = "licenses"
    __table_args__ = (
        db.Index("ix_licenses_status_expires_at", "status", "expires_at"),
        db.Index("ix_licenses_expires_at", "expires_at"),
        db.Index("ix_licenses_created_at", "created_at"),
    )

    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey("customers.id"), nullable=False, index=True)
    plan_id = db.Column(db.Integer, db.ForeignKey("plans.id"), nullable=False, index=True)
    license_key = db.Column(db.String(32), unique=True, nullable=False, index=True)
    status = db.Column(db.String(20), default="active", nullable=False, index=True)
    starts_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    grace_until = db.Column(db.DateTime)
    max_fingerprints = db.Column(db.Integer, default=1, nullable=False)
    allowed_fingerprints_json = db.Column(db.Text, default="[]", nullable=False)
    notes = db.Column(db.Text, default="", nullable=False)
    last_check_at = db.Column(db.DateTime)

    customer = db.relationship("Customer", back_populates="licenses")
    plan = db.relationship("Plan", back_populates="licenses")
    checks = db.relationship("LicenseCheck", back_populates="license", lazy="dynamic")
    renewals = db.relationship("Renewal", back_populates="license", lazy="dynamic")

    @property
    def fingerprints(self) -> list[str]:
        return json_loads(self.allowed_fingerprints_json, [])

    @fingerprints.setter
    def fingerprints(self, value: list[str]) -> None:
        cleaned = [str(v).strip() for v in value if str(v).strip()]
        self.allowed_fingerprints_json = json_dumps(cleaned)


class LicenseCheck(db.Model):
    __tablename__ = "license_checks"
    __table_args__ = (
        db.Index("ix_license_checks_license_checked_at", "license_id", "checked_at"),
        db.Index("ix_license_checks_result_checked_at", "result", "checked_at"),
        db.Index("ix_license_checks_license_ip", "license_id", "ip_address"),
    )

    id = db.Column(db.Integer, primary_key=True)
    license_id = db.Column(db.Integer, db.ForeignKey("licenses.id"), nullable=True, index=True)
    license_key = db.Column(db.String(32), nullable=False, index=True)
    customer_id = db.Column(db.Integer, db.ForeignKey("customers.id"), nullable=True, index=True)
    fingerprint = db.Column(db.String(255), default="", nullable=False, index=True)
    hostname = db.Column(db.String(255), default="", nullable=False)
    ip_address = db.Column(db.String(80), default="", nullable=False)
    version = db.Column(db.String(80), default="", nullable=False)
    install_id = db.Column(db.String(120), default="", nullable=False)
    domain = db.Column(db.String(255), default="", nullable=False)
    result = db.Column(db.String(40), nullable=False, index=True)
    response_mode = db.Column(db.String(20), nullable=False)
    message = db.Column(db.String(255), default="", nullable=False)
    checked_at = db.Column(db.DateTime, default=utcnow, nullable=False, index=True)

    license = db.relationship("License", back_populates="checks")
    customer = db.relationship("Customer")


class Renewal(db.Model):
    __tablename__ = "renewals"
    __table_args__ = (
        db.Index("ix_renewals_customer_created_at", "customer_id", "created_at"),
        db.Index("ix_renewals_license_created_at", "license_id", "created_at"),
    )

    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey("customers.id"), nullable=False, index=True)
    license_id = db.Column(db.Integer, db.ForeignKey("licenses.id"), nullable=False, index=True)
    amount = db.Column(db.Numeric(10, 2), default=0, nullable=False)
    currency = db.Column(db.String(12), default="USD", nullable=False)
    period_months = db.Column(db.Integer, default=1, nullable=False)
    period_start = db.Column(db.DateTime, nullable=False)
    period_end = db.Column(db.DateTime, nullable=False)
    method = db.Column(db.String(40), default="manual", nullable=False)
    status = db.Column(db.String(20), default="paid", nullable=False)
    notes = db.Column(db.Text, default="", nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False, index=True)

    customer = db.relationship("Customer", back_populates="renewals")
    license = db.relationship("License", back_populates="renewals")


class AuditLog(db.Model):
    __tablename__ = "audit_logs"
    __table_args__ = (
        db.Index("ix_audit_logs_entity_created_at", "entity_type", "entity_id", "created_at"),
        db.Index("ix_audit_logs_action_created_at", "action", "created_at"),
    )

    id = db.Column(db.Integer, primary_key=True)
    actor_admin_id = db.Column(db.Integer, db.ForeignKey("admins.id"), nullable=True)
    action = db.Column(db.String(80), nullable=False, index=True)
    entity_type = db.Column(db.String(80), nullable=False, index=True)
    entity_id = db.Column(db.String(80), default="", nullable=False)
    summary = db.Column(db.String(255), default="", nullable=False)
    metadata_json = db.Column(db.Text, default="{}", nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False, index=True)

    actor = db.relationship("Admin")

    @property
    def meta(self) -> dict:
        return json_loads(self.metadata_json, {})

    @meta.setter
    def meta(self, value: dict) -> None:
        self.metadata_json = json_dumps(value or {})


class PlatformPaymentSettings(TimestampMixin, db.Model):
    __tablename__ = "platform_payment_settings"

    id = db.Column(db.Integer, primary_key=True)
    provider = db.Column(db.String(40), default="manual_wallet", nullable=False)
    enabled = db.Column(db.Boolean, default=False, nullable=False)
    wallet_number = db.Column(db.String(120), default="", nullable=False)
    wallet_owner_name = db.Column(db.String(160), default="", nullable=False)
    currency = db.Column(db.String(12), default="USD", nullable=False)
    confirmation_mode = db.Column(db.String(20), default="manual", nullable=False)
    payment_request_ttl_minutes = db.Column(db.Integer, default=1440, nullable=True)


class LicensePaymentRequest(TimestampMixin, db.Model):
    __tablename__ = "license_payment_requests"
    __table_args__ = (
        db.Index("ix_license_payment_requests_status_created", "status", "created_at"),
        db.Index("ix_license_payment_requests_customer", "customer_id", "created_at"),
        db.UniqueConstraint("reference_code", name="uq_license_payment_requests_reference"),
    )

    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey("customers.id"), nullable=False, index=True)
    plan_id = db.Column(db.Integer, db.ForeignKey("plans.id"), nullable=True, index=True)
    license_id = db.Column(db.Integer, db.ForeignKey("licenses.id"), nullable=True, index=True)
    purpose = db.Column(db.String(40), nullable=False)
    amount = db.Column(db.Numeric(10, 2), nullable=False)
    currency = db.Column(db.String(12), default="USD", nullable=False)
    provider = db.Column(db.String(40), default="manual_wallet", nullable=False)
    receiver_wallet = db.Column(db.String(120), default="", nullable=False)
    reference_code = db.Column(db.String(40), nullable=False, index=True)
    access_token = db.Column(db.String(96), default="", nullable=False, index=True)
    status = db.Column(db.String(30), default="pending", nullable=False, index=True)
    expires_at = db.Column(db.DateTime)
    applied_at = db.Column(db.DateTime)
    applied_action = db.Column(db.String(60), default="", nullable=False)
    applied_result_json = db.Column(db.Text, default="{}", nullable=False)

    customer = db.relationship("Customer")
    plan = db.relationship("Plan")
    license = db.relationship("License")
    proofs = db.relationship("LicensePaymentProof", back_populates="payment_request", lazy="dynamic")
    transactions = db.relationship("LicensePaymentTransaction", back_populates="payment_request", lazy="dynamic")
    provisioning_orders = db.relationship("ProvisioningOrder", back_populates="payment_request", lazy="dynamic")


class LicensePaymentProof(db.Model):
    __tablename__ = "license_payment_proofs"
    __table_args__ = (
        db.Index("ix_license_payment_proofs_request", "license_payment_request_id", "submitted_at"),
    )

    id = db.Column(db.Integer, primary_key=True)
    license_payment_request_id = db.Column(db.Integer, db.ForeignKey("license_payment_requests.id"), nullable=False)
    proof_type = db.Column(db.String(40), default="manual_reference", nullable=False)
    reference_number = db.Column(db.String(120), default="", nullable=False)
    image_path = db.Column(db.String(255), default="", nullable=False)
    note = db.Column(db.Text, default="", nullable=False)
    submitted_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    reviewed_by = db.Column(db.Integer, db.ForeignKey("admins.id"), nullable=True)
    reviewed_at = db.Column(db.DateTime)
    review_status = db.Column(db.String(20), default="", nullable=False)
    review_note = db.Column(db.Text, default="", nullable=False)

    payment_request = db.relationship("LicensePaymentRequest", back_populates="proofs")
    reviewer = db.relationship("Admin")


class LicensePaymentTransaction(db.Model):
    __tablename__ = "license_payment_transactions"
    __table_args__ = (
        db.Index("ix_license_payment_transactions_request", "license_payment_request_id", "created_at"),
        db.UniqueConstraint("provider_transaction_id", name="uq_license_payment_transactions_provider_id"),
    )

    id = db.Column(db.Integer, primary_key=True)
    license_payment_request_id = db.Column(db.Integer, db.ForeignKey("license_payment_requests.id"), nullable=False)
    provider_transaction_id = db.Column(db.String(160), nullable=True)
    amount = db.Column(db.Numeric(10, 2), nullable=False)
    currency = db.Column(db.String(12), default="USD", nullable=False)
    status = db.Column(db.String(30), nullable=False)
    raw_payload = db.Column(db.Text, default="{}", nullable=False)
    verified_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)

    payment_request = db.relationship("LicensePaymentRequest", back_populates="transactions")


class LicensePaymentWebhookEvent(db.Model):
    __tablename__ = "license_payment_webhook_events"
    __table_args__ = (
        db.Index("ix_license_payment_webhooks_request", "license_payment_request_id", "created_at"),
        db.UniqueConstraint("provider", "event_id", name="uq_license_payment_webhooks_provider_event"),
    )

    id = db.Column(db.Integer, primary_key=True)
    provider = db.Column(db.String(40), nullable=False)
    event_id = db.Column(db.String(160), nullable=True)
    license_payment_request_id = db.Column(db.Integer, db.ForeignKey("license_payment_requests.id"), nullable=True)
    payload = db.Column(db.Text, default="{}", nullable=False)
    signature_valid = db.Column(db.Boolean, nullable=True)
    processed = db.Column(db.Boolean, default=False, nullable=False)
    processed_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)

    payment_request = db.relationship("LicensePaymentRequest")


class ProvisioningOrder(TimestampMixin, db.Model):
    __tablename__ = "provisioning_orders"
    __table_args__ = (
        db.Index("ix_provisioning_orders_status_created", "status", "created_at"),
        db.Index("ix_provisioning_orders_customer", "customer_id", "created_at"),
    )

    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey("customers.id"), nullable=False, index=True)
    license_payment_request_id = db.Column(db.Integer, db.ForeignKey("license_payment_requests.id"), nullable=True)
    target_plan_id = db.Column(db.Integer, db.ForeignKey("plans.id"), nullable=True)
    status = db.Column(db.String(40), default="payment_pending", nullable=False, index=True)
    requested_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    paid_at = db.Column(db.DateTime)
    provisioning_started_at = db.Column(db.DateTime)
    ready_at = db.Column(db.DateTime)
    delivered_at = db.Column(db.DateTime)
    assigned_operator = db.Column(db.String(160), default="", nullable=False)
    notes = db.Column(db.Text, default="", nullable=False)

    customer = db.relationship("Customer")
    payment_request = db.relationship("LicensePaymentRequest", back_populates="provisioning_orders")
    target_plan = db.relationship("Plan")


class Setting(db.Model):
    __tablename__ = "settings"

    key = db.Column(db.String(120), primary_key=True)
    value = db.Column(db.Text, default="", nullable=False)
    updated_at = db.Column(db.DateTime, default=utcnow, onupdate=utcnow, nullable=False)
