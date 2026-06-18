"""Commercial subscription packages + configurable duration-discount engine.

What the provider SELLS, priced by CONCURRENT-ONLINE capacity — the max number
of simultaneously-connected (live) sessions across ALL session types (cards +
subscribers + broadband/PPPoE + hotspot), NOT the number of accounts created:

  | package (AR)        | concurrent online | $/month |
  | حزمة الكافيهات       | 50                | 10      |
  | حزمة البداية         | 100               | 17      |
  | حزمة الشبكات         | 250               | 25      |
  | حزمة الكبار          | 500               | 35      |
  | حزمة الشركات         | 1000              | 50      |
  | حزمة لا محدودة       | unlimited         | 100     |

The «العرض المجاني» (Free Trial, 14d / 100 concurrent online — see trial_plan.py)
is the entry tier that sits before these.

Packages are seeded as editable Plans (capacity = ``Plan.max_users`` = the
instance-wide concurrent-online ceiling that flows into the capacity contract as
``limits.active_online.max``). Prices + capacities are editable from /admin/plans
like any plan.

Duration discounts apply to ANY package and are ADMIN-CONFIGURABLE (stored as a
JSON Setting, not hardcoded): default 3mo→10%, 6mo→15%, 12mo→20%. The owner can
edit the % per duration and add/remove tiers from «عروض الخصومات».

Effective price = monthly × months × (1 − discount%).
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from decimal import ROUND_HALF_UP, Decimal
from typing import Any, Optional

from ..extensions import db
from ..models import Plan, Setting

#: 0 capacity == unlimited concurrent-online sessions («لا محدودة»).
UNLIMITED = 0

#: (slug, AR name, concurrent-online capacity, monthly USD). Editable afterwards
#: from /admin/plans; this is the idempotent seed baseline.
SUBSCRIPTION_PACKAGES: list[tuple[str, str, int, int]] = [
    ("pkg_cafes",     "حزمة الكافيهات", 50,        10),
    ("pkg_starter",   "حزمة البداية",   100,       17),
    ("pkg_networks",  "حزمة الشبكات",   250,       25),
    ("pkg_large",     "حزمة الكبار",    500,       35),
    ("pkg_companies", "حزمة الشركات",   1000,      50),
    ("pkg_unlimited", "حزمة لا محدودة", UNLIMITED, 100),
]
_PACKAGE_SLUGS = {slug for slug, _n, _c, _p in SUBSCRIPTION_PACKAGES}

#: Setting key holding the editable discount tiers (JSON list).
DISCOUNT_TIERS_SETTING = "subscription.discount_tiers"
DEFAULT_DISCOUNT_TIERS = [
    {"months": 3, "percent": 10, "enabled": True},
    {"months": 6, "percent": 15, "enabled": True},
    {"months": 12, "percent": 20, "enabled": True},
]


class PricingError(ValueError):
    """Raised on invalid discount-tier input."""


# ── packages (Plans) ─────────────────────────────────────────────────────────
def ensure_subscription_packages() -> list[Plan]:
    """Idempotently seed the 6 packages as Plans. Only CREATES missing ones —
    never clobbers prices/capacities the owner edited afterwards."""
    out: list[Plan] = []
    for i, (slug, name, capacity, price) in enumerate(SUBSCRIPTION_PACKAGES):
        plan = Plan.query.filter_by(slug=slug).first()
        if plan is None:
            plan = Plan(name=name, slug=slug, monthly_price=Decimal(price), currency="USD",
                        max_users=capacity, max_nas=10, max_admins=5, max_devices=10,
                        status="active")
            plan.features = {"package": True}
            db.session.add(plan)
            db.session.flush()
        out.append(plan)
    db.session.commit()
    return out


def is_package(plan: Plan | None) -> bool:
    if plan is None:
        return False
    return plan.slug in _PACKAGE_SLUGS or bool((plan.features or {}).get("package"))


def subscription_packages() -> list[Plan]:
    """The package Plans, cheapest first (unlimited last)."""
    plans = [p for p in Plan.query.order_by(Plan.monthly_price.asc()).all() if is_package(p)]
    # unlimited (capacity 0) always last regardless of price
    return sorted(plans, key=lambda p: (p.max_users == UNLIMITED, float(p.monthly_price)))


def capacity_label(capacity: int) -> str:
    return "غير محدود" if int(capacity or 0) == UNLIMITED else f"{int(capacity)} اتصال متزامن"


# ── discount tiers (editable Setting) ────────────────────────────────────────
def get_discount_tiers() -> list[dict[str, Any]]:
    """Editable duration-discount tiers, sorted by months. Falls back to the
    documented defaults when unset/corrupt."""
    row = db.session.get(Setting, DISCOUNT_TIERS_SETTING)
    if not row or not (row.value or "").strip():
        return [dict(t) for t in DEFAULT_DISCOUNT_TIERS]
    try:
        raw = json.loads(row.value)
        tiers = []
        for t in raw:
            tiers.append({
                "months": int(t["months"]),
                "percent": float(t["percent"]),
                "enabled": bool(t.get("enabled", True)),
            })
        return sorted(tiers, key=lambda t: t["months"])
    except (ValueError, KeyError, TypeError):
        return [dict(t) for t in DEFAULT_DISCOUNT_TIERS]


def set_discount_tiers(tiers: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Validate + persist the discount tiers. months 1..120, percent 0..100,
    unique months. Raises PricingError on bad input."""
    cleaned: dict[int, dict[str, Any]] = {}
    for t in tiers:
        try:
            months = int(t["months"])
            percent = float(t["percent"])
        except (KeyError, ValueError, TypeError) as exc:
            raise PricingError("مدخلات الخصم غير صحيحة.") from exc
        if not (1 <= months <= 120):
            raise PricingError("عدد الأشهر يجب أن يكون بين 1 و120.")
        if not (0 <= percent <= 100):
            raise PricingError("نسبة الخصم يجب أن تكون بين 0 و100.")
        cleaned[months] = {"months": months, "percent": percent,
                           "enabled": bool(t.get("enabled", True))}
    ordered = [cleaned[m] for m in sorted(cleaned)]
    row = db.session.get(Setting, DISCOUNT_TIERS_SETTING)
    if row is None:
        row = Setting(key=DISCOUNT_TIERS_SETTING)
        db.session.add(row)
    row.value = json.dumps(ordered, ensure_ascii=False)
    db.session.flush()
    return ordered


def discount_percent_for(months: int) -> float:
    """The enabled discount % for an exact month count (0 when no tier)."""
    for t in get_discount_tiers():
        if t["enabled"] and t["months"] == int(months):
            return float(t["percent"])
    return 0.0


def _money(value: Decimal) -> float:
    return float(Decimal(value).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP))


@dataclass(frozen=True)
class Quote:
    months: int
    monthly: float
    percent: float
    subtotal: float          # monthly × months (before discount)
    total: float             # after discount
    savings: float
    effective_monthly: float  # total / months


def quote(monthly_price: float | Decimal, months: int) -> Quote:
    """Compute a duration quote: monthly × months × (1 − discount%)."""
    months = max(1, int(months))
    monthly = Decimal(str(monthly_price or 0))
    percent = Decimal(str(discount_percent_for(months)))
    subtotal = monthly * months
    total = (subtotal * (Decimal(100) - percent) / Decimal(100))
    return Quote(
        months=months,
        monthly=_money(monthly),
        percent=float(percent),
        subtotal=_money(subtotal),
        total=_money(total),
        savings=_money(subtotal - total),
        effective_monthly=_money(total / months),
    )


def package_pricing() -> list[dict[str, Any]]:
    """Pricing-UI data: each package with its monthly price + a quote per
    enabled discount tier (plus the 1-month baseline)."""
    tier_months = [1] + [t["months"] for t in get_discount_tiers() if t["enabled"]]
    out: list[dict[str, Any]] = []
    for plan in subscription_packages():
        monthly = float(plan.monthly_price or 0)
        out.append({
            "plan": plan,
            "name": plan.name,
            "capacity": int(plan.max_users or 0),
            "capacity_label": capacity_label(plan.max_users or 0),
            "unlimited": int(plan.max_users or 0) == UNLIMITED,
            "monthly": _money(Decimal(str(monthly))),
            "quotes": [quote(monthly, m) for m in tier_months],
        })
    return out


__all__ = [
    "SUBSCRIPTION_PACKAGES", "UNLIMITED", "DISCOUNT_TIERS_SETTING", "DEFAULT_DISCOUNT_TIERS",
    "PricingError", "Quote",
    "ensure_subscription_packages", "is_package", "subscription_packages", "capacity_label",
    "get_discount_tiers", "set_discount_tiers", "discount_percent_for", "quote", "package_pricing",
]
