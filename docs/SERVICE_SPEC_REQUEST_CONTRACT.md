# Smart Service Activate / Upgrade Spec-Requests — Contract
**Status:** LIVE on the panel portal (feat/services-catalog-policy) · mirror spec for the radius-module client
**Date:** 2026-06-12

> Owner requirement: «نفس فكرة الترقية + طلب التفعيل — في الريدياس وفي صفحة
> العميل بلوحة التراخيص. التفعيل = طلب يحدد مواصفات معينة، والترقية = ترقية
> لمواصفات معينة. اجعلها ذكية لكل خدمة.»

ACTIVATION (طلب تفعيل) = a REQUEST that selects target specs for a not-yet-
active service. UPGRADE (ترقية) = a request to RAISE the specs of an active /
free-limited service (pre-filled with current values; floor = current). Both
produce a `CustomerServiceRequest` in the owner's inbox carrying structured
`desired_limits` + a human-readable Arabic summary.

---

## 1. The SMART per-type spec schema (single source of truth)

`app/services/customer_control.py::service_spec_fields(service_key)` returns
the form schema for one service type:

```jsonc
[
  {
    "key": "max_total",            // form field name → spec_<key>; desired_limits key
    "label": "أقصى عدد مشتركين",   // Arabic label
    "hint": "عدد المشتركين المسموح إنشاؤهم.",
    "min": 10,                     // sensible per-type floor (activation)
    "max": 100000,                 // per-type ceiling (server clamps too)
    "step": 10,
    "default": 100,                // pre-fill for ACTIVATION
    "unit": "مشترك"               // display badge (LTR-safe)
  }
]
```

It is the union of:
- the service's entitlement limit fields (`SERVICE_LIMIT_FIELDS`) enriched
  with `SERVICE_SPEC_META` bounds/defaults/units, and
- request-only extras (`SERVICE_REQUEST_EXTRA_FIELDS`) for types whose specs
  are not entitlement limits — e.g. `ip_change_vpn` carries per-direction
  speed (`download_mbps` ↓ / `upload_mbps` ↑ — independent directions, per
  the fleet per-direction speed rule), `max_vpn_users`, optional `quota_gb`.

Only relevant fields exist per type (a cards service asks counts; a bandwidth
service asks speeds/quota; a whatsapp service asks message caps). Services
with NO fields render a "no quantitative specs — we'll contact you" notice.

**Modal behaviour (panel portal — implemented in `portal_pro.js`):**
- ACTIVATION: each field pre-filled with `default`, bounded `[min, max]`.
- UPGRADE: pre-filled with the CURRENT limit; floor is raised to the current
  value (`min = max(min, current)`) — upgrades only go up; `data-current-limits`
  comes from the serialized service payload.

## 2. Request submission — panel portal (live)

```
POST /portal/services/<service_key>/request          (portal session)
Content-Type: application/x-www-form-urlencoded

request_type = "activation" | "upgrade"
spec_<key>   = <int>        // one per schema field the customer set
notes        = "<free text>"            // optional
```

Server behaviour (`app/public/routes.py::customer_portal_service_request`):
parses ONLY keys present in `service_spec_fields(service_key)`, ints only,
clamped to `[min, max]`; builds `desired_limits = {key: value}`; prepends the
Arabic summary («المواصفات المطلوبة — السرعة: 100 Mbps ↓، …») to the notes;
creates the `CustomerServiceRequest` (status `pending`, type as posted).

## 3. Mirror contract — radius-module client (TO IMPLEMENT, radius side)

The radius client implements the SAME flow against the EXISTING bridge
endpoint (no new panel endpoint needed):

```
POST {PANEL}/api/integration/hoberadius/service-requests     (HTTPS)
{
  "license_key": "HBR-2026-…",          // bearer auth (SIMPLE_LINK_CONTRACT)
  "service_key": "subscribers",
  "request_type": "activation" | "upgrade",
  "notes": "المواصفات المطلوبة — أقصى عدد مشتركين: 500 مشترك\n\n<user notes>",
  "desired_limits": {"max_total": 500}
}
→ 201 {"ok": true, "status": "pending",
       "service_request": {"id", "reference", "title", "service_key",
                            "request_type", "status"}}
```

(Panel handler: `app/api/routes.py::hoberadius_service_requests` — already
accepts `desired_limits` dict + `request_type` + `notes` verbatim.)

To render the SAME smart form, the radius client needs the schema. Source it
from the runtime contract: each serialized service already carries
`limits` (current) + `tier` + `upgradable`; the SCHEMA (labels/bounds/units)
ships as a static mirror of `service_spec_fields` in the radius repo —
regenerate it from this panel module when fields change (single Python dict,
copy-paste freshness is acceptable v1; a `service-spec-schema` bridge
endpoint is the v2 option if drift ever bites).

Client UX mirror rules:
- Activation visible when service `enabled == false` and `tier == "paid"`.
- Upgrade visible when `upgradable == true` (free_limited) or enabled paid.
- HIDDEN services (`hidden == true` in the contract payload) are not shown
  at all — mirror the portal's omission.

## 4. desired_limits semantics for the owner/provisioner

`desired_limits` keys are the SAME keys used by entitlement limits — approving
a request is therefore mechanical: copy the approved values onto
`CustomerServiceEntitlement.limits` (the service-request admin flow) and the
contract + portal + radius enforcement update on the next sync. Extras that
are not entitlement limits (e.g. `download_mbps`) are provisioning inputs for
the service's own pipeline (VPN contract) and stay visible in the request
summary either way.
