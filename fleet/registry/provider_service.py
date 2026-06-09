"""fleet.registry.provider_service — CRUD + validation for fleet hosting providers.

Phase 3 / P3-T6. Business logic for the ``fleet_providers`` table (the hosting
companies + their bandwidth cost model). Routes in
``fleet.registry.routes_provider`` are thin parse→call→jsonify wrappers over this.

Cost-model rules (docs/chr_fleet/02_DATA_MODEL.md §2.2):

  * ``open``    — unlimited / flat: no per-TB price, no monthly cap, no overage.
                  We normalise price_per_tb→0, monthly_cap_tb→NULL, overage→False.
  * ``metered`` — priced per TB with an optional monthly cap; ``overage_allowed``
                  decides whether usage may exceed the cap (at ``overage_price_per_tb``).

All mutators validate, then commit. Errors are raised as ``ProviderError``
subclasses so the route layer can map them to 400/404/409 without leaking
SQLAlchemy internals.
"""
from __future__ import annotations

from decimal import Decimal, InvalidOperation
from typing import Any

from app.extensions import db
from app.models import utcnow
from fleet.registry.models_chr import (
    PROVIDER_COST_MODELS,
    FleetChrNode,
    FleetProvider,
)


# ──────────────────────────────────────────────────────────────────────────────
# Errors
# ──────────────────────────────────────────────────────────────────────────────
class ProviderError(ValueError):
    """Base class for provider validation/CRUD errors (maps to HTTP 400)."""


class ProviderNotFound(ProviderError):
    """No provider with the given id/name (maps to HTTP 404)."""


class ProviderNameTaken(ProviderError):
    """Another provider already uses this name (maps to HTTP 409)."""


class ProviderInUse(ProviderError):
    """Provider still has CHR nodes attached; cannot delete (maps to HTTP 409)."""


# ──────────────────────────────────────────────────────────────────────────────
# Coercion helpers
# ──────────────────────────────────────────────────────────────────────────────
def _clean_name(value: Any) -> str:
    name = str(value or "").strip()
    if not name:
        raise ProviderError("اسم المزوّد مطلوب.")
    if len(name) > 120:
        raise ProviderError("اسم المزوّد طويل جداً (الحد 120 حرفاً).")
    return name


def _to_decimal(value: Any, field: str, *, allow_none: bool = True) -> Decimal | None:
    if value is None or value == "":
        if allow_none:
            return None
        raise ProviderError(f"{field} مطلوب.")
    try:
        dec = Decimal(str(value))
    except (InvalidOperation, TypeError) as exc:
        raise ProviderError(f"{field} يجب أن يكون رقماً.") from exc
    if dec < 0:
        raise ProviderError(f"{field} لا يمكن أن يكون سالباً.")
    return dec


def _to_cycle_day(value: Any) -> int:
    if value in (None, ""):
        return 1
    try:
        day = int(value)
    except (TypeError, ValueError) as exc:
        raise ProviderError("يوم دورة الفوترة يجب أن يكون رقماً.") from exc
    if not 1 <= day <= 28:
        raise ProviderError("يوم دورة الفوترة يجب أن يكون بين 1 و 28.")
    return day


def _normalize_cost_fields(
    cost_model: str,
    *,
    price_per_tb: Any,
    monthly_cap_tb: Any,
    overage_allowed: Any,
    overage_price_per_tb: Any,
) -> dict[str, Any]:
    """Validate the cost model and coerce the dependent money/cap fields.

    Returns a dict of normalised column values. ``open`` providers are flattened
    to "no charge, no cap"; ``metered`` keeps the supplied price/cap/overage.
    """
    model = str(cost_model or "").strip().lower()
    if model not in PROVIDER_COST_MODELS:
        raise ProviderError(
            f"نموذج التكلفة يجب أن يكون أحد {PROVIDER_COST_MODELS}."
        )

    if model == "open":
        # Unlimited/flat: ignore any price/cap/overage the caller sent.
        return {
            "cost_model": "open",
            "price_per_tb": Decimal("0"),
            "monthly_cap_tb": None,
            "overage_allowed": False,
            "overage_price_per_tb": None,
        }

    # metered
    price = _to_decimal(price_per_tb, "السعر لكل تيرابايت", allow_none=False)
    cap = _to_decimal(monthly_cap_tb, "السقف الشهري (TB)")
    over = bool(overage_allowed)
    over_price = _to_decimal(overage_price_per_tb, "سعر التجاوز لكل TB")
    if over and over_price is None:
        # Allowing overage without a price is a silent billing hole — reject it.
        raise ProviderError("عند السماح بالتجاوز يجب تحديد سعر التجاوز لكل TB.")
    return {
        "cost_model": "metered",
        "price_per_tb": price,
        "monthly_cap_tb": cap,
        "overage_allowed": over,
        "overage_price_per_tb": over_price,
    }


# ──────────────────────────────────────────────────────────────────────────────
# Reads
# ──────────────────────────────────────────────────────────────────────────────
def list_providers() -> list[FleetProvider]:
    """All providers, ordered by name."""
    return FleetProvider.query.order_by(FleetProvider.name).all()


def get_provider(provider_id: int) -> FleetProvider | None:
    return db.session.get(FleetProvider, int(provider_id))


def get_provider_or_404(provider_id: int) -> FleetProvider:
    prov = get_provider(provider_id)
    if prov is None:
        raise ProviderNotFound(f"لا يوجد مزوّد بالمعرّف {provider_id}.")
    return prov


def get_provider_by_name(name: str) -> FleetProvider | None:
    return FleetProvider.query.filter_by(name=str(name or "").strip()).one_or_none()


def node_count(provider_id: int) -> int:
    return FleetChrNode.query.filter_by(provider_id=provider_id).count()


# ──────────────────────────────────────────────────────────────────────────────
# Mutations
# ──────────────────────────────────────────────────────────────────────────────
def create_provider(
    *,
    name: str,
    cost_model: str,
    price_per_tb: Any = 0,
    monthly_cap_tb: Any = None,
    overage_allowed: Any = False,
    overage_price_per_tb: Any = None,
    billing_cycle_day: Any = 1,
    api_creds_ref: str | None = None,
) -> FleetProvider:
    """Create a provider. Raises ``ProviderNameTaken`` on a duplicate name."""
    clean_name = _clean_name(name)
    if get_provider_by_name(clean_name) is not None:
        raise ProviderNameTaken(f"يوجد مزوّد بالاسم «{clean_name}» مسبقاً.")

    cost = _normalize_cost_fields(
        cost_model,
        price_per_tb=price_per_tb,
        monthly_cap_tb=monthly_cap_tb,
        overage_allowed=overage_allowed,
        overage_price_per_tb=overage_price_per_tb,
    )
    prov = FleetProvider(
        name=clean_name,
        billing_cycle_day=_to_cycle_day(billing_cycle_day),
        api_creds_ref=(str(api_creds_ref).strip() or None) if api_creds_ref else None,
        **cost,
    )
    db.session.add(prov)
    db.session.commit()
    return prov


def update_provider(provider_id: int, **fields: Any) -> FleetProvider:
    """Partial update. Only the keys present in ``fields`` are touched.

    Recognised keys: name, cost_model, price_per_tb, monthly_cap_tb,
    overage_allowed, overage_price_per_tb, billing_cycle_day, api_creds_ref.
    """
    prov = get_provider_or_404(provider_id)

    if "name" in fields:
        clean_name = _clean_name(fields["name"])
        clash = get_provider_by_name(clean_name)
        if clash is not None and clash.id != prov.id:
            raise ProviderNameTaken(f"يوجد مزوّد بالاسم «{clean_name}» مسبقاً.")
        prov.name = clean_name

    # If any cost-related field is being changed, re-normalise the whole group so
    # we never end up with e.g. a metered price on an 'open' provider.
    cost_keys = {
        "cost_model", "price_per_tb", "monthly_cap_tb",
        "overage_allowed", "overage_price_per_tb",
    }
    if cost_keys & fields.keys():
        cost = _normalize_cost_fields(
            fields.get("cost_model", prov.cost_model),
            price_per_tb=fields.get("price_per_tb", prov.price_per_tb),
            monthly_cap_tb=fields.get("monthly_cap_tb", prov.monthly_cap_tb),
            overage_allowed=fields.get("overage_allowed", prov.overage_allowed),
            overage_price_per_tb=fields.get("overage_price_per_tb", prov.overage_price_per_tb),
        )
        for key, value in cost.items():
            setattr(prov, key, value)

    if "billing_cycle_day" in fields:
        prov.billing_cycle_day = _to_cycle_day(fields["billing_cycle_day"])
    if "api_creds_ref" in fields:
        ref = fields["api_creds_ref"]
        prov.api_creds_ref = (str(ref).strip() or None) if ref else None

    prov.updated_at = utcnow()
    db.session.commit()
    return prov


def delete_provider(provider_id: int) -> None:
    """Delete a provider. Refuses (``ProviderInUse``) if CHR nodes reference it."""
    prov = get_provider_or_404(provider_id)
    attached = node_count(prov.id)
    if attached:
        raise ProviderInUse(
            f"لا يمكن حذف المزوّد: مرتبط به {attached} عقدة CHR. انقل/احذف العقد أولاً."
        )
    db.session.delete(prov)
    db.session.commit()


def upsert_provider_by_name(
    name: str,
    *,
    cost_model: str,
    **cost_fields: Any,
) -> FleetProvider:
    """Get the provider named ``name`` or create it. Used by the onboarding wizard
    so the "Provider: select/new" field transparently creates a row.

    If the provider exists, its cost model is left as-is (the wizard does not
    silently rewrite an existing provider's billing); only a brand-new provider
    takes the supplied cost fields.
    """
    existing = get_provider_by_name(name)
    if existing is not None:
        return existing
    return create_provider(name=name, cost_model=cost_model, **cost_fields)


def to_dict(prov: FleetProvider) -> dict[str, Any]:
    """JSON-serialisable view of a provider (for the route layer)."""
    def _num(value):
        return None if value is None else float(value)

    return {
        "id": prov.id,
        "name": prov.name,
        "cost_model": prov.cost_model,
        "price_per_tb": _num(prov.price_per_tb),
        "monthly_cap_tb": _num(prov.monthly_cap_tb),
        "overage_allowed": bool(prov.overage_allowed),
        "overage_price_per_tb": _num(prov.overage_price_per_tb),
        "billing_cycle_day": prov.billing_cycle_day,
        "api_creds_ref": prov.api_creds_ref,
        "node_count": node_count(prov.id),
    }


__all__ = [
    "ProviderError",
    "ProviderNotFound",
    "ProviderNameTaken",
    "ProviderInUse",
    "list_providers",
    "get_provider",
    "get_provider_or_404",
    "get_provider_by_name",
    "node_count",
    "create_provider",
    "update_provider",
    "delete_provider",
    "upsert_provider_by_name",
    "to_dict",
]
