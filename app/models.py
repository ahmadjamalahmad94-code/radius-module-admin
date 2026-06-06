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
    # Elevated admin: required to create/rotate/reveal Customer Secure Vault secrets.
    is_super_admin = db.Column(db.Boolean, default=False, nullable=False)
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
    currency = db.Column(db.String(12), default="USD", nullable=False)
    notes = db.Column(db.Text, default="", nullable=False)
    status = db.Column(db.String(20), default="active", nullable=False, index=True)
    portal_config_json = db.Column(db.Text, default="{}", nullable=False)

    @property
    def portal_config(self) -> dict:
        return json_loads(self.portal_config_json, {})

    @portal_config.setter
    def portal_config(self, value: dict) -> None:
        self.portal_config_json = json_dumps(value or {})

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
    # سوبر يوزر صريح: عند تفعيله يضمن الجسر أن مستخدم الراديوس يصبح
    # is_super_admin = 1 على راديوس العميل دائماً (كل الأقسام مفتوحة)، بصرف النظر
    # عن الدور. مالك الحساب (owner) يبقى سوبر ضمنياً للتوافق مع السلوك القديم.
    is_super = db.Column(db.Boolean, default=False, nullable=False, index=True)
    active = db.Column(db.Boolean, default=True, nullable=False, index=True)
    last_password_changed_at = db.Column(db.DateTime, default=utcnow, nullable=False)

    customer = db.relationship("Customer", back_populates="users")

    @property
    def is_effective_super(self) -> bool:
        """السوبر الفعلي: العلم الصريح is_super أو دور المالك (توافقاً مع القديم)."""
        return bool(self.is_super) or self.role_key == "owner"

    def set_password(self, password: str, *, increment_version: bool = True) -> None:
        self.password_hash = generate_password_hash(password)
        self.password_hash_scheme = "werkzeug"
        self.last_password_changed_at = utcnow()
        if increment_version:
            self.password_version = int(self.password_version or 0) + 1

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)


class CustomerRadiusAdmin(TimestampMixin, db.Model):
    """لقطة (snapshot) عن حساب أدمن موجود محلياً على راديوس العميل.

    حسابات أدمن الراديوس تُنشأ وتُدار محلياً على راديوس العميل — خصوصاً الأدمن
    الرئيسي المحلي (``external_identity_provider == ""`` و
    ``managed_by_license_admin == 0``) — فلا تعرفها لوحة التراخيص أصلاً. عبر
    القناة العكسية للجسر (مثل رفع النسخ الاحتياطية) يبلّغ الراديوسُ اللوحةَ بجرد
    أدمنياته، فتخزّن اللوحة هذه اللقطة لأجل العرض والتحكم. اللقطة للعرض فقط ولا
    تمثّل مصدر الحقيقة لكلمات المرور أبداً.

    ``force_super`` هو تحكّم اللوحة: عند تفعيله تُدفع تعليمة صريحة للراديوس عبر
    عقد مزامنة الهوية ليجعل ``is_super_admin = 1`` لهذا الأدمن في كل دورة مزامنة
    (idempotent)، دون المساس بكلمة مروره أو مزوّد هويته — فلا ينكسر دخوله المحلي.
    """
    __tablename__ = "customer_radius_admins"
    __table_args__ = (
        db.UniqueConstraint("customer_id", "radius_admin_id", name="uq_customer_radius_admins_customer_rid"),
        db.Index("ix_customer_radius_admins_customer_enabled", "customer_id", "enabled"),
    )

    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey("customers.id"), nullable=False, index=True)
    license_id = db.Column(db.Integer, db.ForeignKey("licenses.id"), nullable=True, index=True)
    # المعرّف كما هو على راديوس العميل — المفتاح المستقر للمطابقة وتطبيق الفرض.
    radius_admin_id = db.Column(db.Integer, nullable=False)
    username = db.Column(db.String(80), default="", nullable=False)
    role = db.Column(db.String(40), default="", nullable=False)
    # آخر حالة سوبر أبلغ عنها الراديوس (للعرض فقط).
    is_super_admin = db.Column(db.Boolean, default=False, nullable=False)
    enabled = db.Column(db.Boolean, default=True, nullable=False)
    # هل هذا هو الأدمن الرئيسي المحلي للراديوس (حساب الإدارة الأساسي). يبلّغ به
    # الراديوس كي يظهر مميَّزاً في «أدمن الراديوس» بعرض العميل 360.
    is_primary = db.Column(db.Boolean, default=False, nullable=False)
    # هل الأدمن مُدار أصلاً من لوحة التراخيص (هوية مُزامَنة) أم محلي بحت.
    managed_by_license_admin = db.Column(db.Boolean, default=False, nullable=False)
    external_identity_provider = db.Column(db.String(40), default="", nullable=False)
    # تحكّم اللوحة: فرض is_super_admin=1 على الراديوس عبر الجسر (idempotent).
    force_super = db.Column(db.Boolean, default=False, nullable=False, index=True)
    last_seen_at = db.Column(db.DateTime, nullable=True)

    customer = db.relationship("Customer")
    license = db.relationship("License")

    @property
    def is_effective_super(self) -> bool:
        """السوبر الفعلي المعروض: فرض اللوحة أو ما أبلغ عنه الراديوس فعلاً."""
        return bool(self.force_super) or bool(self.is_super_admin)


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
    messages = db.relationship(
        "CustomerServiceRequestMessage",
        back_populates="service_request",
        cascade="all, delete-orphan",
        lazy="dynamic",
    )

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


class CustomerServiceRequestMessage(TimestampMixin, db.Model):
    __tablename__ = "customer_service_request_messages"
    __table_args__ = (
        db.Index("ix_customer_service_request_messages_request_created", "service_request_id", "created_at"),
        db.Index("ix_customer_service_request_messages_customer_created", "customer_id", "created_at"),
    )

    id = db.Column(db.Integer, primary_key=True)
    service_request_id = db.Column(db.Integer, db.ForeignKey("customer_service_requests.id"), nullable=False, index=True)
    customer_id = db.Column(db.Integer, db.ForeignKey("customers.id"), nullable=False, index=True)
    admin_id = db.Column(db.Integer, db.ForeignKey("admins.id"), nullable=True, index=True)
    customer_user_id = db.Column(db.Integer, db.ForeignKey("customer_users.id"), nullable=True, index=True)
    sender_type = db.Column(db.String(30), default="system", nullable=False, index=True)
    event_type = db.Column(db.String(60), default="message", nullable=False, index=True)
    body = db.Column(db.Text, default="", nullable=False)
    internal = db.Column(db.Boolean, default=False, nullable=False)
    metadata_json = db.Column(db.Text, default="{}", nullable=False)

    service_request = db.relationship("CustomerServiceRequest", back_populates="messages")
    customer = db.relationship("Customer")
    admin = db.relationship("Admin")
    customer_user = db.relationship("CustomerUser")

    @property
    def message_metadata(self) -> dict:
        return json_loads(self.metadata_json, {})

    @message_metadata.setter
    def message_metadata(self, value: dict) -> None:
        self.metadata_json = json_dumps(value or {})


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


class ChrSpeedProfile(TimestampMixin, db.Model):
    """بروفايل سرعة مركزي يديره المالك ويُطابَق إلى ``/ppp/profile`` على CHR.

    جوهر المنتج هو التحكّم بالسرعة: لكل بروفايل سرعةُ تنزيل/رفع (Mbps) تُترجَم إلى
    ``rate-limit`` على بروفايل PPP على CHR (idempotent). يختار المدير عند إنشاء النفق
    بروفايلًا جاهزًا أو يُدخل سرعة مخصّصة. هذه إعدادات مركزية لا تُرسَل لأي لوحة عميل.
    """
    __tablename__ = "chr_speed_profiles"
    __table_args__ = (
        db.Index("ix_chr_speed_profiles_active_code", "active", "code"),
    )

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(140), nullable=False)
    code = db.Column(db.String(80), unique=True, nullable=False, index=True)
    download_mbps = db.Column(db.Integer, nullable=False)
    upload_mbps = db.Column(db.Integer, nullable=False)
    # حدّ الجلسات المتزامنة الافتراضي لهذا البروفايل (اختياري؛ النفق قد يتجاوزه).
    max_sessions = db.Column(db.Integer, nullable=True)
    # اسم /ppp/profile المقابل على CHR (يُشتق إن تُرك فارغًا: hob-<code>).
    chr_profile_name = db.Column(db.String(80), default="", nullable=False)
    active = db.Column(db.Boolean, default=True, nullable=False, index=True)
    notes = db.Column(db.String(255), default="", nullable=False)

    tunnels = db.relationship("CustomerVpnTunnel", back_populates="speed_profile", lazy="dynamic")

    @property
    def effective_chr_profile_name(self) -> str:
        return (self.chr_profile_name or f"hob-{self.code}").strip()


class CustomerVpnTunnel(TimestampMixin, db.Model):
    """A concrete VPN tunnel account provisioned CENTRALLY on the owner's CHR.

    This is the *implementation* layer beneath ``CustomerVpnEntitlement`` (which
    is the commercial allowance: speed/users/locations). One row = one real
    account created on the central MikroTik CHR (a ``/ppp/secret`` for
    SSTP/PPTP/L2TP). The username/password are generated here and pushed to the
    CHR via the RouterOS REST API; the customer panel pulls them over the signed
    bridge and injects them into its own RADIUS — credentials and CHR access NEVER
    live in the customer panel.

    The password is stored ENCRYPTED (Fernet, ``CUSTOMER_VAULT_ENCRYPTION_KEY``)
    and only ever returned in clear over the bridge to the owning license, and
    only until the customer acknowledges delivery (``delivery_status`` flips to
    ``delivered``). Operators see a masked hint, never the clear password.
    """
    __tablename__ = "customer_vpn_tunnels"
    __table_args__ = (
        db.UniqueConstraint("username", name="uq_customer_vpn_tunnels_username"),
        db.Index("ix_customer_vpn_tunnels_customer_status", "customer_id", "status"),
        db.Index("ix_customer_vpn_tunnels_delivery", "customer_id", "delivery_status"),
    )

    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey("customers.id"), nullable=False, index=True)
    license_id = db.Column(db.Integer, db.ForeignKey("licenses.id"), nullable=True, index=True)
    # sstp | pptp | l2tp | ipsec  (ipsec is recorded-only in P1; see vpn_tunnels.py)
    tunnel_type = db.Column(db.String(20), default="sstp", nullable=False, index=True)
    username = db.Column(db.String(80), nullable=False)
    # Fernet ciphertext ONLY — never plaintext.
    password_encrypted = db.Column(db.Text, nullable=False)
    password_hint = db.Column(db.String(40), default="", nullable=False)
    profile = db.Column(db.String(80), default="default", nullable=False)
    # How many simultaneous connections this account is allowed (member's quota).
    max_connections = db.Column(db.Integer, default=1, nullable=False)
    # Speed control (the core of the product). The chosen down/up (Mbps) and the
    # RouterOS rate-limit string actually applied on the CHR /ppp/profile. NULL/empty
    # means "no explicit speed" (default profile, unshaped).
    speed_profile_id = db.Column(db.Integer, db.ForeignKey("chr_speed_profiles.id"), nullable=True, index=True)
    download_mbps = db.Column(db.Integer, nullable=True)
    upload_mbps = db.Column(db.Integer, nullable=True)
    rate_limit = db.Column(db.String(80), default="", nullable=False)
    # ── Monthly traffic quota with THROTTLE-on-exhaust (IP-change tunnels carry
    # high bandwidth; the owner caps GB/month). NULL/0 quota = unlimited. When the
    # month's usage reaches the quota the tunnel is moved to a low throttle speed
    # (NOT disconnected); the monthly worker resets usage at the start of each
    # month and restores full speed. Usage is sampled by polling the live CHR
    # session (accurate for an always-on tunnel).
    monthly_quota_gb = db.Column(db.Integer, nullable=True)
    throttle_down_mbps = db.Column(db.Integer, nullable=True)
    throttle_up_mbps = db.Column(db.Integer, nullable=True)
    # Usage accounting (best-effort, sampled): YYYY-MM period + bytes this period.
    quota_period = db.Column(db.String(7), default="", nullable=False)
    quota_bytes_used = db.Column(db.BigInteger, default=0, nullable=False)
    # Live-sample baseline: bytes of the current CHR session already counted, so
    # re-polling the same session doesn't double-count (session counters reset on
    # reconnect, so we add deltas).
    quota_sample_bytes = db.Column(db.BigInteger, default=0, nullable=False)
    is_throttled = db.Column(db.Boolean, default=False, nullable=False)
    # pending | active | suspended | revoked | failed
    status = db.Column(db.String(20), default="pending", nullable=False, index=True)
    # auto (bridge SSTP) | manual (admin PPTP/IPsec)
    provisioning = db.Column(db.String(20), default="auto", nullable=False)
    # bridge_request | admin_manual
    source = db.Column(db.String(30), default="bridge_request", nullable=False)
    # Whether the account was actually created on the CHR (False for ipsec/record-only).
    chr_provisioned = db.Column(db.Boolean, default=False, nullable=False)
    chr_secret_id = db.Column(db.String(40), default="", nullable=False)
    chr_host = db.Column(db.String(255), default="", nullable=False)
    remote_address = db.Column(db.String(64), default="", nullable=False)
    # pending | delivered — at-least-once delivery of the clear password over the bridge.
    delivery_status = db.Column(db.String(20), default="pending", nullable=False, index=True)
    delivered_at = db.Column(db.DateTime, nullable=True)
    requested_by_user_id = db.Column(db.Integer, db.ForeignKey("customer_users.id"), nullable=True)
    created_by_admin_id = db.Column(db.Integer, db.ForeignKey("admins.id"), nullable=True)
    last_error = db.Column(db.String(255), default="", nullable=False)
    notes = db.Column(db.Text, default="", nullable=False)

    customer = db.relationship("Customer")
    license = db.relationship("License")
    speed_profile = db.relationship("ChrSpeedProfile", back_populates="tunnels")


class CustomerBackupArtifact(TimestampMixin, db.Model):
    """A database backup uploaded by a customer's RADIUS instance to the panel.

    Stored in the customer's file so the operator always has an off-site copy
    of each instance's local backup. Metadata is always recorded; the actual
    SQLite file is stored on disk only when the instance uploaded its content.
    """
    __tablename__ = "customer_backup_artifacts"
    __table_args__ = (
        db.UniqueConstraint("customer_id", "backup_reference", name="uq_customer_backup_reference"),
        db.Index("ix_customer_backup_artifacts_customer_created", "customer_id", "created_at"),
    )

    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey("customers.id"), nullable=False, index=True)
    license_id = db.Column(db.Integer, db.ForeignKey("licenses.id"), nullable=True, index=True)
    license_key = db.Column(db.String(64), default="", nullable=False, index=True)
    backup_reference = db.Column(db.String(160), default="", nullable=False)
    module = db.Column(db.String(60), default="radius-module", nullable=False)
    instance_id = db.Column(db.String(120), default="", nullable=False)
    kind = db.Column(db.String(40), default="sqlite", nullable=False)
    size = db.Column(db.Integer, default=0, nullable=False)
    checksum_sha256 = db.Column(db.String(64), default="", nullable=False)
    upload_mode = db.Column(db.String(40), default="metadata_only", nullable=False)
    content_included = db.Column(db.Boolean, default=False, nullable=False)
    stored_filename = db.Column(db.String(255), default="", nullable=False)
    result_status = db.Column(db.String(40), default="received", nullable=False)
    metadata_json = db.Column(db.Text, default="{}", nullable=False)
    remote_created_at = db.Column(db.String(40), default="", nullable=False)
    received_at = db.Column(db.DateTime, default=utcnow, nullable=False)

    customer = db.relationship("Customer")
    license = db.relationship("License")

    @property
    def artifact_metadata(self) -> dict:
        return json_loads(self.metadata_json, {})

    @artifact_metadata.setter
    def artifact_metadata(self, value: dict) -> None:
        self.metadata_json = json_dumps(value or {})

    @property
    def has_content(self) -> bool:
        return bool(self.content_included and self.stored_filename)


class CustomerGoogleDrive(TimestampMixin, db.Model):
    """Per-customer Google Drive OAuth connection for cloud backups.

    The refresh token is stored ENCRYPTED (Fernet) and is never exposed to
    admins. Each customer connects their own Drive; backups upload only to
    that customer's own Drive folder (scope drive.file).
    """
    __tablename__ = "customer_google_drive"

    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey("customers.id"), unique=True, nullable=False, index=True)
    connected = db.Column(db.Boolean, default=False, nullable=False)
    google_email = db.Column(db.String(255), default="", nullable=False)
    refresh_token_enc = db.Column(db.Text, default="", nullable=False)
    folder_id = db.Column(db.String(120), default="", nullable=False)
    folder_name = db.Column(db.String(180), default="HobeRadius Backups", nullable=False)
    scopes = db.Column(db.String(500), default="", nullable=False)
    connected_at = db.Column(db.DateTime, nullable=True)
    last_upload_at = db.Column(db.DateTime, nullable=True)
    last_error = db.Column(db.String(500), default="", nullable=False)

    customer = db.relationship("Customer")


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
    max_fingerprints = db.Column(db.Integer, default=3, nullable=False)
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


class WhatsAppTenantAccount(TimestampMixin, db.Model):
    """Per-customer WhatsApp Business / Cloud API connection state.

    One account per customer. Holds the provider linkage (Meta Cloud API by
    default), the encrypted access token + webhook secrets, and the live
    connection/quality health that the gateway reads before sending.
    """
    __tablename__ = "whatsapp_tenant_accounts"
    __table_args__ = (
        db.UniqueConstraint("customer_id", name="uq_whatsapp_tenant_accounts_customer"),
        db.Index("ix_whatsapp_tenant_accounts_phone_number_id", "phone_number_id"),
    )

    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey("customers.id"), nullable=False, index=True)
    license_id = db.Column(db.Integer, db.ForeignKey("licenses.id"), nullable=True, index=True)
    provider = db.Column(db.String(40), default="meta_cloud", nullable=False)
    connection_status = db.Column(db.String(20), default="disconnected", nullable=False, index=True)
    meta_business_id = db.Column(db.String(120), nullable=True)
    whatsapp_business_account_id = db.Column(db.String(120), nullable=True)
    phone_number_id = db.Column(db.String(120), nullable=True)
    display_phone_number = db.Column(db.String(40), nullable=True)
    business_display_name = db.Column(db.String(180), nullable=True)
    access_token_encrypted = db.Column(db.Text, nullable=True)
    token_expires_at = db.Column(db.DateTime, nullable=True)
    webhook_verify_token_hash = db.Column(db.String(190), nullable=True)
    webhook_secret_encrypted = db.Column(db.Text, nullable=True)
    quality_rating = db.Column(db.String(20), nullable=True)
    messaging_limit_tier = db.Column(db.String(40), nullable=True)
    last_health_check_at = db.Column(db.DateTime, nullable=True)
    last_error_code = db.Column(db.String(60), nullable=True)
    last_error_message = db.Column(db.Text, nullable=True)
    connected_at = db.Column(db.DateTime, nullable=True)
    disconnected_at = db.Column(db.DateTime, nullable=True)
    # How the connection was established: "manual" (admin pasted credentials,
    # legacy/advanced path) or "embedded" (Meta Embedded Signup self-service).
    onboarding_method = db.Column(db.String(20), default="manual", nullable=False)
    # Space-separated OAuth scopes granted during embedded signup.
    scopes = db.Column(db.Text, nullable=True)
    # Last time the connection health/metadata was synced from Meta.
    last_sync_at = db.Column(db.DateTime, nullable=True)

    customer = db.relationship("Customer")
    license = db.relationship("License")


class WhatsAppEmbeddedSignupAttempt(TimestampMixin, db.Model):
    """A single Meta Embedded Signup onboarding attempt (state/nonce session).

    Hardens the self-service flow: before the browser opens Meta's popup the
    backend issues a one-time ``state`` + ``nonce`` and records a *pending*
    attempt here. The completion callback must echo a ``state`` that matches a
    live (non-expired, non-consumed) attempt for the SAME session customer,
    which is then marked ``completed``/``failed``. This binds the popup to the
    server session and makes a replayed/forged callback fail closed.

    Only SHA-256 *hashes* of the state/nonce are stored (mirrors
    ``WhatsAppTenantAccount.webhook_verify_token_hash``); the raw values are
    handed to the browser once and never persisted in clear.

    Additive + feature-flagged: when embedded signup is disabled, nothing
    writes here and the legacy flow is untouched.
    """
    __tablename__ = "whatsapp_embedded_signup_attempts"
    __table_args__ = (
        db.UniqueConstraint("state_hash", name="uq_whatsapp_embedded_attempts_state_hash"),
    )

    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey("customers.id"), nullable=False, index=True)
    license_id = db.Column(db.Integer, db.ForeignKey("licenses.id"), nullable=True, index=True)
    # SHA-256 hex digests of the one-time state + nonce (raw values never stored).
    state_hash = db.Column(db.String(128), nullable=False)
    nonce_hash = db.Column(db.String(128), nullable=True)
    # pending -> completed | failed | expired
    status = db.Column(db.String(20), default="pending", nullable=False, index=True)
    error_code = db.Column(db.String(60), nullable=True)
    error_message = db.Column(db.Text, nullable=True)
    # The customer_user who started the attempt ("initiated_by user id").
    initiated_by = db.Column(db.Integer, db.ForeignKey("customer_users.id"), nullable=True)
    expires_at = db.Column(db.DateTime, nullable=True)
    completed_at = db.Column(db.DateTime, nullable=True)

    customer = db.relationship("Customer")
    license = db.relationship("License")


class WhatsAppServiceSettings(TimestampMixin, db.Model):
    """Per-customer WhatsApp gateway plan + policy switches.

    One row per customer describing the enabled plan, message-rate ceilings,
    the per-category send permissions, quiet-hours, and opt-in policy that the
    gateway enforces before queuing/sending.
    """
    __tablename__ = "whatsapp_service_settings"
    __table_args__ = (
        db.UniqueConstraint("customer_id", name="uq_whatsapp_service_settings_customer"),
    )

    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey("customers.id"), nullable=False, index=True)
    license_id = db.Column(db.Integer, db.ForeignKey("licenses.id"), nullable=True)
    enabled = db.Column(db.Boolean, default=False, nullable=False, index=True)
    plan_code = db.Column(db.String(40), default="whatsapp_basic", nullable=False, index=True)
    monthly_message_limit = db.Column(db.Integer, default=500)
    daily_message_limit = db.Column(db.Integer, default=100)
    per_minute_limit = db.Column(db.Integer, default=10)
    allow_otp = db.Column(db.Boolean, default=True)
    allow_expiry_notice = db.Column(db.Boolean, default=True)
    allow_quota_notice = db.Column(db.Boolean, default=True)
    allow_maintenance_notice = db.Column(db.Boolean, default=True)
    allow_password_reset = db.Column(db.Boolean, default=True)
    allow_bulk_utility = db.Column(db.Boolean, default=False)
    allow_marketing = db.Column(db.Boolean, default=False)
    require_subscriber_opt_in = db.Column(db.Boolean, default=True)
    quiet_hours_enabled = db.Column(db.Boolean, default=False)
    quiet_hours_start = db.Column(db.String(5), nullable=True)
    quiet_hours_end = db.Column(db.String(5), nullable=True)
    timezone = db.Column(db.String(60), default="Asia/Hebron")

    customer = db.relationship("Customer")
    license = db.relationship("License")


class WhatsAppTemplate(TimestampMixin, db.Model):
    """A WhatsApp message template (local definition + Meta sync state).

    Each customer maps a local_key (e.g. ``otp``) to a provider template in a
    given language. ``variables_schema`` describes the placeholder slots; the
    Meta-side id/status are mirrored back after submission/approval.
    """
    __tablename__ = "whatsapp_templates"
    __table_args__ = (
        db.UniqueConstraint("customer_id", "local_key", "language", name="uq_whatsapp_templates_customer_key_lang"),
        db.Index("ix_whatsapp_templates_customer_id", "customer_id"),
        db.Index("ix_whatsapp_templates_status", "status"),
    )

    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey("customers.id"), nullable=False)
    license_id = db.Column(db.Integer, db.ForeignKey("licenses.id"), nullable=True)
    local_key = db.Column(db.String(60), nullable=False)
    provider_template_name = db.Column(db.String(190), nullable=True)
    language = db.Column(db.String(12), default="ar", nullable=False)
    category = db.Column(db.String(20), default="UTILITY", nullable=False)
    status = db.Column(db.String(20), default="draft", nullable=False)
    body_preview = db.Column(db.Text, nullable=True)
    variables_schema_json = db.Column(db.Text, nullable=True)
    meta_template_id = db.Column(db.String(120), nullable=True)
    last_synced_at = db.Column(db.DateTime, nullable=True)

    customer = db.relationship("Customer")
    license = db.relationship("License")

    @property
    def variables_schema(self):
        return json_loads(self.variables_schema_json, {})

    @variables_schema.setter
    def variables_schema(self, value) -> None:
        self.variables_schema_json = json_dumps(value or {})


class WhatsAppMessageQueue(TimestampMixin, db.Model):
    """Outbound WhatsApp message queue with delivery lifecycle + retries.

    Every send request lands here first. ``idempotency_key`` dedups requests
    from upstream systems; ``status`` walks queued -> sending -> sent ->
    delivered/read or failed, with attempt/backoff bookkeeping and the
    provider message id used to correlate webhook status callbacks.
    """
    __tablename__ = "whatsapp_message_queue"
    __table_args__ = (
        db.Index("ix_whatsapp_message_queue_status_next_attempt", "status", "next_attempt_at"),
        db.Index("ix_whatsapp_message_queue_customer_created", "customer_id", "created_at"),
    )

    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey("customers.id"), nullable=False, index=True)
    license_id = db.Column(db.Integer, db.ForeignKey("licenses.id"), nullable=True)
    source_system = db.Column(db.String(40), nullable=False)
    source_event_type = db.Column(db.String(60), nullable=False, index=True)
    subscriber_id = db.Column(db.String(120), nullable=True)
    recipient_phone = db.Column(db.String(40), nullable=False)
    normalized_recipient_phone = db.Column(db.String(40), nullable=False, index=True)
    template_key = db.Column(db.String(60), nullable=True)
    template_name = db.Column(db.String(190), nullable=True)
    language = db.Column(db.String(12), default="ar")
    variables_json = db.Column(db.Text, nullable=True)
    raw_body = db.Column(db.Text, nullable=True)
    priority = db.Column(db.Integer, default=5)
    status = db.Column(db.String(20), default="queued", nullable=False)
    provider_message_id = db.Column(db.String(190), nullable=True, index=True)
    idempotency_key = db.Column(db.String(190), nullable=False, unique=True)
    error_code = db.Column(db.String(60), nullable=True)
    error_message = db.Column(db.Text, nullable=True)
    attempts = db.Column(db.Integer, default=0)
    max_attempts = db.Column(db.Integer, default=3)
    next_attempt_at = db.Column(db.DateTime, nullable=True)
    sent_at = db.Column(db.DateTime, nullable=True)
    delivered_at = db.Column(db.DateTime, nullable=True)
    read_at = db.Column(db.DateTime, nullable=True)
    failed_at = db.Column(db.DateTime, nullable=True)

    customer = db.relationship("Customer")
    license = db.relationship("License")

    @property
    def variables(self):
        return json_loads(self.variables_json, {})

    @variables.setter
    def variables(self, value) -> None:
        self.variables_json = json_dumps(value or {})


class WhatsAppWebhookEvent(TimestampMixin, db.Model):
    """Raw inbound webhook events from the provider, stored for dedup + replay.

    Meta delivers status callbacks, inbound messages, and template/account
    updates here. ``event_id`` enforces Meta-side dedup; ``payload`` keeps the
    full JSON so processing can be retried idempotently.
    """
    __tablename__ = "whatsapp_webhook_events"
    __table_args__ = (
        db.UniqueConstraint("event_id", name="uq_whatsapp_webhook_events_event_id"),
    )

    id = db.Column(db.Integer, primary_key=True)
    provider = db.Column(db.String(40), default="meta_cloud")
    event_type = db.Column(db.String(40), nullable=False, index=True)
    phone_number_id = db.Column(db.String(120), nullable=True, index=True)
    provider_message_id = db.Column(db.String(190), nullable=True, index=True)
    customer_id = db.Column(db.Integer, db.ForeignKey("customers.id"), nullable=True, index=True)
    event_id = db.Column(db.String(190), nullable=True, unique=True)
    payload_json = db.Column(db.Text, nullable=False)
    processed = db.Column(db.Boolean, default=False, index=True)
    processing_error = db.Column(db.Text, nullable=True)
    received_at = db.Column(db.DateTime, nullable=False)
    processed_at = db.Column(db.DateTime, nullable=True)

    customer = db.relationship("Customer")

    @property
    def payload(self):
        return json_loads(self.payload_json, {})

    @payload.setter
    def payload(self, value) -> None:
        self.payload_json = json_dumps(value or {})


class WhatsAppSubscriberPreference(TimestampMixin, db.Model):
    """Per-subscriber WhatsApp consent + per-category notification prefs.

    Tracks whether a subscriber opted in, which message categories they
    accept, and whether they are blocked. Unique per (customer, subscriber).
    """
    __tablename__ = "whatsapp_subscriber_preferences"
    __table_args__ = (
        db.UniqueConstraint("customer_id", "subscriber_id", name="uq_whatsapp_subscriber_preferences_customer_subscriber"),
        db.Index("ix_whatsapp_subscriber_preferences_normalized_phone", "normalized_phone"),
        db.Index("ix_whatsapp_subscriber_preferences_opt_in", "whatsapp_opt_in"),
    )

    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey("customers.id"), nullable=False, index=True)
    subscriber_id = db.Column(db.String(120), nullable=False)
    phone = db.Column(db.String(40), nullable=True)
    normalized_phone = db.Column(db.String(40), nullable=True)
    whatsapp_opt_in = db.Column(db.Boolean, default=False)
    allow_otp = db.Column(db.Boolean, default=True)
    allow_service_notices = db.Column(db.Boolean, default=True)
    allow_maintenance = db.Column(db.Boolean, default=True)
    allow_marketing = db.Column(db.Boolean, default=False)
    blocked = db.Column(db.Boolean, default=False)
    opted_in_at = db.Column(db.DateTime, nullable=True)
    opted_out_at = db.Column(db.DateTime, nullable=True)
    source = db.Column(db.String(40), nullable=True)

    customer = db.relationship("Customer")


class WhatsAppUsageCounter(TimestampMixin, db.Model):
    """Aggregated send counters per customer per period (daily/monthly).

    Backs quota enforcement and reporting. Unique per
    (customer, period_type, period_key) where period_key is e.g. ``2026-06``
    for monthly or ``2026-06-01`` for daily.
    """
    __tablename__ = "whatsapp_usage_counters"
    __table_args__ = (
        db.UniqueConstraint("customer_id", "period_type", "period_key", name="uq_whatsapp_usage_counters_customer_period"),
        db.Index("ix_whatsapp_usage_counters_period_type", "period_type"),
        db.Index("ix_whatsapp_usage_counters_period_key", "period_key"),
    )

    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey("customers.id"), nullable=False, index=True)
    period_type = db.Column(db.String(10), nullable=False)
    period_key = db.Column(db.String(20), nullable=False)
    queued_count = db.Column(db.Integer, default=0)
    sent_count = db.Column(db.Integer, default=0)
    delivered_count = db.Column(db.Integer, default=0)
    failed_count = db.Column(db.Integer, default=0)

    customer = db.relationship("Customer")


class Setting(db.Model):
    __tablename__ = "settings"

    key = db.Column(db.String(120), primary_key=True)
    value = db.Column(db.Text, default="", nullable=False)
    updated_at = db.Column(db.DateTime, default=utcnow, onupdate=utcnow, nullable=False)


# ─────────────────────────────────────────────────────────────────────────
# Customer Secure Vault — ADMIN-ONLY. NEVER exposed to customers, the customer
# portal, or any public/integration API. Two data classes:
#   • customer_private_records : admin-only operational notes/links (not secrets)
#   • customer_secret_vault    : per-customer secrets, ENCRYPTED at rest
#   • customer_vault_audit_logs: dedicated audit trail for vault actions
# Plaintext secrets are never stored here; only Fernet ciphertext in
# encrypted_secret. See app/services/customer_vault_crypto.py.
# ─────────────────────────────────────────────────────────────────────────

class CustomerPrivateRecord(TimestampMixin, db.Model):
    __tablename__ = "customer_private_records"
    __table_args__ = (
        db.Index("ix_cpr_customer", "customer_id"),
        db.Index("ix_cpr_type", "record_type"),
        db.Index("ix_cpr_flags", "is_archived", "is_pinned"),
    )

    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey("customers.id"), nullable=False, index=True)
    record_type = db.Column(db.String(40), nullable=False, default="other")
    title = db.Column(db.String(160), nullable=False)
    value = db.Column(db.Text, default="", nullable=False)
    url = db.Column(db.String(500), default="", nullable=False)
    notes = db.Column(db.Text, default="", nullable=False)
    is_pinned = db.Column(db.Boolean, default=False, nullable=False)
    is_archived = db.Column(db.Boolean, default=False, nullable=False)
    created_by_admin_id = db.Column(db.Integer, db.ForeignKey("admins.id"), nullable=True)
    updated_by_admin_id = db.Column(db.Integer, db.ForeignKey("admins.id"), nullable=True)


class CustomerSecret(TimestampMixin, db.Model):
    __tablename__ = "customer_secret_vault"
    __table_args__ = (
        db.Index("ix_csv_customer", "customer_id"),
        db.Index("ix_csv_type", "secret_type"),
        db.Index("ix_csv_status", "status"),
        db.Index("ix_csv_revealed", "last_revealed_at"),
    )

    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey("customers.id"), nullable=False, index=True)
    secret_type = db.Column(db.String(40), nullable=False, default="other")
    label = db.Column(db.String(160), nullable=False)
    host = db.Column(db.String(255), default="", nullable=False)
    url = db.Column(db.String(500), default="", nullable=False)
    username = db.Column(db.String(160), default="", nullable=False)
    # Fernet ciphertext ONLY — never plaintext.
    encrypted_secret = db.Column(db.Text, nullable=False)
    secret_hint = db.Column(db.String(160), default="", nullable=False)
    notes = db.Column(db.Text, default="", nullable=False)
    status = db.Column(db.String(20), default="active", nullable=False)  # active|rotated|revoked|archived
    last_revealed_at = db.Column(db.DateTime, nullable=True)
    last_revealed_by_admin_id = db.Column(db.Integer, db.ForeignKey("admins.id"), nullable=True)
    last_rotated_at = db.Column(db.DateTime, nullable=True)
    created_by_admin_id = db.Column(db.Integer, db.ForeignKey("admins.id"), nullable=True)
    updated_by_admin_id = db.Column(db.Integer, db.ForeignKey("admins.id"), nullable=True)


class CustomerVaultAuditLog(db.Model):
    __tablename__ = "customer_vault_audit_logs"
    __table_args__ = (
        db.Index("ix_cval_customer_created", "customer_id", "created_at"),
        db.Index("ix_cval_actor", "actor_admin_id"),
        db.Index("ix_cval_action", "action"),
        db.Index("ix_cval_target", "target_type", "target_id"),
    )

    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey("customers.id"), nullable=False, index=True)
    actor_admin_id = db.Column(db.Integer, db.ForeignKey("admins.id"), nullable=True)
    action = db.Column(db.String(60), nullable=False)
    target_type = db.Column(db.String(40), nullable=False)  # private_record | secret
    target_id = db.Column(db.Integer, nullable=True)
    ip_address = db.Column(db.String(64), default="", nullable=False)
    user_agent = db.Column(db.String(255), default="", nullable=False)
    reason = db.Column(db.String(255), default="", nullable=False)
    metadata_json = db.Column(db.Text, default="{}", nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False, index=True)

    actor = db.relationship("Admin")

    @property
    def meta(self) -> dict:
        return json_loads(self.metadata_json, {})

    @meta.setter
    def meta(self, value: dict) -> None:
        self.metadata_json = json_dumps(value or {})
# Landing Page CMS — admin-editable public landing content
# All visible marketing content is driven from these tables (not hardcoded).
# JSON is stored as Text + property accessors (project convention). The name
# "metadata" is reserved by SQLAlchemy, so JSON props are named settings/features.
# ─────────────────────────────────────────────────────────────────────────

class LandingPage(TimestampMixin, db.Model):
    __tablename__ = "landing_pages"
    __table_args__ = (
        db.Index("ix_landing_pages_slug_status", "slug", "status"),
    )

    id = db.Column(db.Integer, primary_key=True)
    slug = db.Column(db.String(120), unique=True, nullable=False, index=True)
    title = db.Column(db.String(180), default="", nullable=False)
    language = db.Column(db.String(8), default="ar", nullable=False)
    status = db.Column(db.String(20), default="draft", nullable=False, index=True)  # draft|published|archived
    seo_title = db.Column(db.String(200), default="", nullable=False)
    seo_description = db.Column(db.String(400), default="", nullable=False)
    seo_keywords = db.Column(db.String(400), default="", nullable=False)
    og_image_url = db.Column(db.String(500), default="", nullable=False)
    is_homepage = db.Column(db.Boolean, default=False, nullable=False, index=True)
    published_at = db.Column(db.DateTime, nullable=True)

    sections = db.relationship(
        "LandingSection", back_populates="page",
        cascade="all, delete-orphan", lazy="dynamic",
    )
    revisions = db.relationship(
        "LandingRevision", back_populates="page",
        cascade="all, delete-orphan", lazy="dynamic",
    )


class LandingSection(TimestampMixin, db.Model):
    __tablename__ = "landing_sections"
    __table_args__ = (
        db.Index("ix_landing_sections_page_order", "page_id", "sort_order"),
        db.UniqueConstraint("page_id", "section_key", name="uq_landing_section_key"),
    )

    id = db.Column(db.Integer, primary_key=True)
    page_id = db.Column(db.Integer, db.ForeignKey("landing_pages.id"), nullable=False, index=True)
    section_key = db.Column(db.String(60), nullable=False)
    section_type = db.Column(db.String(40), default="cards_grid", nullable=False)
    eyebrow_text = db.Column(db.String(140), default="", nullable=False)
    title = db.Column(db.String(220), default="", nullable=False)
    subtitle = db.Column(db.String(320), default="", nullable=False)
    description = db.Column(db.Text, default="", nullable=False)
    badge_text = db.Column(db.String(80), default="", nullable=False)
    primary_button_text = db.Column(db.String(80), default="", nullable=False)
    primary_button_url = db.Column(db.String(300), default="", nullable=False)
    secondary_button_text = db.Column(db.String(80), default="", nullable=False)
    secondary_button_url = db.Column(db.String(300), default="", nullable=False)
    image_url = db.Column(db.String(500), default="", nullable=False)
    icon_name = db.Column(db.String(60), default="", nullable=False)
    background_style = db.Column(db.String(40), default="", nullable=False)
    sort_order = db.Column(db.Integer, default=100, nullable=False)
    is_visible = db.Column(db.Boolean, default=True, nullable=False)
    settings_json = db.Column(db.Text, default="{}", nullable=False)

    page = db.relationship("LandingPage", back_populates="sections")
    items = db.relationship(
        "LandingItem", back_populates="section",
        cascade="all, delete-orphan", lazy="dynamic",
    )

    @property
    def settings(self) -> dict:
        return json_loads(self.settings_json, {})

    @settings.setter
    def settings(self, value: dict) -> None:
        self.settings_json = json_dumps(value or {})


class LandingItem(TimestampMixin, db.Model):
    __tablename__ = "landing_items"
    __table_args__ = (
        db.Index("ix_landing_items_section_order", "section_id", "sort_order"),
    )

    id = db.Column(db.Integer, primary_key=True)
    section_id = db.Column(db.Integer, db.ForeignKey("landing_sections.id"), nullable=False, index=True)
    item_type = db.Column(db.String(40), default="feature", nullable=False)
    title = db.Column(db.String(220), default="", nullable=False)
    subtitle = db.Column(db.String(320), default="", nullable=False)
    description = db.Column(db.Text, default="", nullable=False)
    value_text = db.Column(db.String(120), default="", nullable=False)
    label_text = db.Column(db.String(120), default="", nullable=False)
    icon_name = db.Column(db.String(60), default="", nullable=False)
    image_url = db.Column(db.String(500), default="", nullable=False)
    button_text = db.Column(db.String(80), default="", nullable=False)
    button_url = db.Column(db.String(300), default="", nullable=False)
    badge_text = db.Column(db.String(80), default="", nullable=False)
    status_badge = db.Column(db.String(40), default="", nullable=False)  # متاح|قيد التجهيز|حسب الخطة|قريبًا
    price_text = db.Column(db.String(80), default="", nullable=False)
    old_price_text = db.Column(db.String(80), default="", nullable=False)
    period_text = db.Column(db.String(80), default="", nullable=False)
    features_json = db.Column(db.Text, default="[]", nullable=False)
    settings_json = db.Column(db.Text, default="{}", nullable=False)
    sort_order = db.Column(db.Integer, default=100, nullable=False)
    is_visible = db.Column(db.Boolean, default=True, nullable=False)

    section = db.relationship("LandingSection", back_populates="items")

    @property
    def features(self) -> list:
        return json_loads(self.features_json, [])

    @features.setter
    def features(self, value) -> None:
        self.features_json = json_dumps(value or [])

    @property
    def settings(self) -> dict:
        return json_loads(self.settings_json, {})

    @settings.setter
    def settings(self, value: dict) -> None:
        self.settings_json = json_dumps(value or {})


class LandingSocialLink(TimestampMixin, db.Model):
    __tablename__ = "landing_social_links"

    id = db.Column(db.Integer, primary_key=True)
    platform = db.Column(db.String(40), nullable=False)  # facebook|instagram|whatsapp|telegram|...
    label = db.Column(db.String(120), default="", nullable=False)
    url = db.Column(db.String(500), default="", nullable=False)
    icon_name = db.Column(db.String(60), default="", nullable=False)
    sort_order = db.Column(db.Integer, default=100, nullable=False)
    is_visible = db.Column(db.Boolean, default=True, nullable=False)


class LandingContactMethod(TimestampMixin, db.Model):
    __tablename__ = "landing_contact_methods"

    id = db.Column(db.Integer, primary_key=True)
    method_type = db.Column(db.String(40), nullable=False)  # phone|whatsapp|email|address|support_url
    label = db.Column(db.String(120), default="", nullable=False)
    value = db.Column(db.String(300), default="", nullable=False)
    url = db.Column(db.String(500), default="", nullable=False)
    icon_name = db.Column(db.String(60), default="", nullable=False)
    sort_order = db.Column(db.Integer, default=100, nullable=False)
    is_visible = db.Column(db.Boolean, default=True, nullable=False)


class LandingRevision(db.Model):
    __tablename__ = "landing_revisions"
    __table_args__ = (
        db.Index("ix_landing_revisions_page_created", "page_id", "created_at"),
    )

    id = db.Column(db.Integer, primary_key=True)
    page_id = db.Column(db.Integer, db.ForeignKey("landing_pages.id"), nullable=True, index=True)
    snapshot_json = db.Column(db.Text, default="{}", nullable=False)
    created_by = db.Column(db.String(120), default="", nullable=False)
    note = db.Column(db.String(255), default="", nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False, index=True)

    page = db.relationship("LandingPage", back_populates="revisions")

    @property
    def snapshot(self) -> dict:
        return json_loads(self.snapshot_json, {})

    @snapshot.setter
    def snapshot(self, value: dict) -> None:
        self.snapshot_json = json_dumps(value or {})
