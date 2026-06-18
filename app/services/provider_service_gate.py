"""Provider→radius service-gate mapping for the capacity contract.

THE PROBLEM
-----------
The provider catalog has ~45 services (``subscribers``, ``whatsapp_gateway``,
``routers``, …). The radius web-admin "sell-services" gate only understands 14
section keys (``subscribers``, ``cards``, ``reports``, ``finance``, ``network``,
``store``, ``communications``, ``access_control``, ``anti_mac_clone``,
``backups``, ``service_requests``, ``tools``, ``settings``, ``customer_portal``).

So a provider service the owner set to «موقوفة» (suspended) reaches the radius
under a key the gate never checks — and the section stays visible. This module
aggregates the already-serialized provider ``services`` map into a
``provider_grants`` block keyed by the 14 radius gate keys, which the radius
gate consults directly.

WHERE THE MAP LIVES (decision)
------------------------------
On the PROVIDER side (here). The provider owns the catalog, knows the
disable/hide/limit state, and the catalog will keep growing — the radius gate
should just read its 14 keys. We still document the mapping
(docs/contracts/PROVIDER_SERVICE_GATE_MAP.md) so the radius session has it.

AGGREGATION SEMANTICS
---------------------
Several provider services can feed one gate key. We aggregate from the FINAL
serialized service entries (post plan-features / tier / suspend / license), so:
  * enabled = OR of mapped services  (section stays available while ANY of its
    capabilities is granted; the owner gates the whole section by disabling all
    of them);
  * status  = "active" if any enabled; else "locked_upgrade" (+ requires_activation)
    when something is paid-but-not-purchased (a visible upsell — the radius shows
    it LOCKED with a «طلب تفعيل/ترقية» CTA, NOT hidden); else "disabled" — which
    happens ONLY for an explicit «موقوفة» suspend (radius hard-hides + 403);
  * hidden  = all mapped services hidden (hide the section only when everything
    feeding it is hidden);
  * limits  = merged limits of the mapped services.

A gate key with NO mapped provider service (e.g. ``anti_mac_clone``) is OMITTED
so the radius gate applies its own default (enabled) — the provider never
controls it.
"""
from __future__ import annotations

from typing import Any

#: The provider "paid, not-yet-purchased" tier (matches
#: customer_control.SERVICE_TIER_PAID). A paid service that's off is a visible
#: upsell (``locked_upgrade``), never a hard ``disabled``.
PAID_TIER = "paid"

#: The radius web-admin gate keys (the 14 sections it can hide / 403).
RADIUS_GATE_KEYS: tuple[str, ...] = (
    "subscribers", "cards", "reports", "finance", "network", "store",
    "communications", "access_control", "anti_mac_clone", "backups",
    "service_requests", "tools", "settings", "customer_portal",
)

#: Provider catalog service_key → radius gate key. Every provider service that
#: should influence a radius section is listed; unmapped provider services
#: (pure provider-side concerns like integration_bridge internals) simply don't
#: contribute to any gate. ``anti_mac_clone`` has no provider service → never
#: appears in provider_grants (radius default-enables it).
PROVIDER_TO_GATE: dict[str, str] = {
    # ── subscribers ──
    "subscribers": "subscribers",
    "subscriber_groups": "subscribers",
    "sessions": "subscribers",
    # ── cards ──
    "cards": "cards",
    "print_templates": "cards",
    # ── reports ──
    "reports": "reports",
    # ── finance ──
    "accounting": "finance",
    "invoices": "finance",
    "payment_collection": "finance",
    "finance_center": "finance",
    "vouchers": "finance",
    # ── network ──
    "routers": "network",
    "nas": "network",
    "profiles": "network",
    "ip_pools": "network",
    "network_policies": "network",
    "bandwidth_control": "network",
    "site_exit": "network",
    "public_ip_change": "network",
    "ip_change_vpn": "network",
    "remote_access": "network",
    # ── store (sales / marketplace) ──
    "card_marketplace": "store",
    "card_users": "store",
    "cards_recharge": "store",
    "distributors": "store",
    # ── communications ──
    "communications": "communications",
    "whatsapp_gateway": "communications",
    # ── access_control (admins / security) ──
    "admins": "access_control",
    "audit_logs": "access_control",
    "risk_events": "access_control",
    # ── backups (+ archival/retention) ──
    "backups": "backups",
    "lifecycle": "backups",
    # ── service_requests (support / tickets) ──
    "customer_support": "service_requests",
    # ── tools (diagnostics / remote ops) ──
    "router_diagnostics": "tools",
    "remote_support": "tools",
    "remote_health_fix": "tools",
    "operations_center": "tools",
    # ── settings (setup / integration / tenancy) ──
    "setup_wizard": "settings",
    "integration_bridge": "settings",
    "webhooks": "settings",
    "integration_tokens": "settings",
    "multi_tenant": "settings",
    # ── customer_portal ──
    "customer_portal": "customer_portal",
    "radius_customer_portals": "customer_portal",
}

#: Arabic labels for the gate keys (documentation / optional UI).
GATE_LABELS: dict[str, str] = {
    "subscribers": "المشتركون",
    "cards": "الكروت",
    "reports": "التقارير",
    "finance": "المالية",
    "network": "الشبكة",
    "store": "المتجر",
    "communications": "الاتصالات",
    "access_control": "التحكم بالوصول",
    "anti_mac_clone": "منع استنساخ MAC",
    "backups": "النسخ الاحتياطي",
    "service_requests": "طلبات الخدمة",
    "tools": "الأدوات",
    "settings": "الإعدادات",
    "customer_portal": "بوابة العميل",
}


def build_provider_grants(services: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Aggregate the serialized provider ``services`` map into a map keyed by
    the 14 radius gate keys. See module docstring for the semantics.

    ``services`` is the output of ``_services_contract`` — each value a dict
    with at least ``enabled``/``status`` and optional ``hidden``/``limits``.
    Returns only gate keys that at least one provider service maps to.
    """
    # Collect the serialized entries feeding each gate key.
    buckets: dict[str, list[tuple[str, dict[str, Any]]]] = {}
    for provider_key, entry in (services or {}).items():
        gate = PROVIDER_TO_GATE.get(provider_key)
        if gate is None or not isinstance(entry, dict):
            continue
        buckets.setdefault(gate, []).append((provider_key, entry))

    grants: dict[str, dict[str, Any]] = {}
    for gate, items in buckets.items():
        any_enabled = any(bool(e.get("enabled")) for _k, e in items)
        any_suspended = any(e.get("status") == "suspended" for _k, e in items)
        all_hidden = bool(items) and all(bool(e.get("hidden")) for _k, e in items)
        # A «مدفوعة» (paid) service that isn't purchased yet is OFF but is a
        # visible upsell — NOT a hard block. It's a lock/upgrade candidate when
        # it's off, paid-tier, and not explicitly suspended (expired paid still
        # counts — it's re-purchasable). Free services auto-enable, so an
        # off-not-suspended service is in practice always a paid lock.
        any_paid_locked = any(
            (not e.get("enabled")) and e.get("tier") == PAID_TIER and e.get("status") != "suspended"
            for _k, e in items
        )

        # State priority (sell-services model):
        #   active        — at least one capability is granted/working;
        #   locked_upgrade — nothing on, but something is purchasable → show
        #                    the section LOCKED with a «طلب تفعيل/ترقية» CTA;
        #   disabled      — ONLY when the section is explicitly «موقوفة» (or
        #                    off with nothing sellable) → radius hard-hides+403.
        requires_activation = False
        if any_enabled:
            status = "active"
        elif any_paid_locked:
            status = "locked_upgrade"
            requires_activation = True
        elif any_suspended:
            status = "disabled"
        else:
            status = "disabled"

        merged_limits: dict[str, Any] = {}
        for _k, e in items:
            lim = e.get("limits")
            if isinstance(lim, dict):
                merged_limits.update(lim)

        grant: dict[str, Any] = {
            "enabled": any_enabled,
            "status": status,
            # Distinct from `disabled`: the radius shows a locked section with an
            # upgrade CTA instead of hard-hiding+403.
            "requires_activation": requires_activation,
            "hidden": all_hidden,
            # The provider services that fed this gate key — useful for the
            # radius/operator to see why a section is gated.
            "services": sorted(k for k, _e in items),
        }
        if merged_limits:
            grant["limits"] = merged_limits
        grants[gate] = grant

    return grants


__all__ = ["RADIUS_GATE_KEYS", "PROVIDER_TO_GATE", "GATE_LABELS", "build_provider_grants"]
