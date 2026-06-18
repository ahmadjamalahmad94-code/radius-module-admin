# Provider → radius service-gate mapping

The licensing/provider panel (radius-module-admin) catalog has ~45 services.
The customer's radius web-admin "sell-services" gate understands **14** section
keys. The capacity contract now emits a `provider_grants` block keyed by those
14 keys so a disabled / hidden / limited provider service reaches the radius
under a key its gate actually reads.

- **Builder:** `app/services/customer_control.py::build_runtime_contract_for_license`
  → adds `contract["provider_grants"]` + `contract["fingerprint"]`.
- **Aggregator + map:** `app/services/provider_service_gate.py`.
- **Bridge endpoint:** `POST /api/integration/hoberadius/capacity-contract`
  returns `provider_grants` and `fingerprint` at the top level (alongside
  `services` / `limits`). The heartbeat
  (`/api/integration/hoberadius/instance-ops/heartbeat`) returns
  `capacity_fingerprint` so the radius can re-pull promptly after a change.

## Where the map lives

**On the provider side (here).** The provider owns the catalog, knows the
disable/hide/limit state, and the catalog keeps growing — the radius gate
should just read its 14 keys. This document is the reference for the radius
session; the radius gate does **not** need its own alias table.

## Aggregation semantics

`provider_grants[gate]` is aggregated from the **final serialized** provider
service entries (post plan-features / tier / suspend / license), so:

| field | rule |
|---|---|
| `enabled` | **OR** of mapped services — the section stays available while ANY of its capabilities is granted; the owner gates the whole section by disabling all of them. |
| `status` | `active` if any enabled, else `suspended` if any suspended, else `disabled`. |
| `hidden` | **all** mapped services hidden (hide the section only when everything feeding it is hidden). |
| `limits` | merged limits of the mapped services. |
| `services` | the provider keys that fed this gate (for diagnostics). |

A gate key with **no** mapped provider service is **omitted** from
`provider_grants`, so the radius gate applies its own default (enabled). Today
that is only `anti_mac_clone` — the provider never controls it.

## The 14 radius gate keys → provider services

| radius gate key | provider services mapped to it |
|---|---|
| `subscribers` | `subscribers`, `subscriber_groups`, `sessions` |
| `cards` | `cards`, `print_templates` |
| `reports` | `reports` |
| `finance` | `accounting`, `invoices`, `payment_collection`, `finance_center`, `vouchers` |
| `network` | `routers`, `nas`, `profiles`, `ip_pools`, `network_policies`, `bandwidth_control`, `site_exit`, `public_ip_change`, `ip_change_vpn`, `remote_access` |
| `store` | `card_marketplace`, `card_users`, `cards_recharge`, `distributors` |
| `communications` | `communications`, `whatsapp_gateway` |
| `access_control` | `admins`, `audit_logs`, `risk_events` |
| `anti_mac_clone` | *(none — radius default-enables it)* |
| `backups` | `backups`, `lifecycle` |
| `service_requests` | `customer_support` |
| `tools` | `router_diagnostics`, `remote_support`, `remote_health_fix`, `operations_center` |
| `settings` | `setup_wizard`, `integration_bridge`, `webhooks`, `integration_tokens`, `multi_tenant` |
| `customer_portal` | `customer_portal`, `radius_customer_portals` |

## Example `provider_grants` in the contract

```json
"provider_grants": {
  "reports":        {"enabled": false, "status": "suspended", "hidden": false, "services": ["reports"]},
  "communications": {"enabled": false, "status": "disabled",  "hidden": false, "services": ["communications", "whatsapp_gateway"]},
  "subscribers":    {"enabled": true,  "status": "active",    "hidden": false, "services": ["sessions", "subscriber_groups", "subscribers"], "limits": {"max_total": 500}}
},
"fingerprint": "9f2c…"
```

## Propagation after a tariff save

The contract is computed **live** on every pull (no provider-side cache), so a
saved tariff is reflected on the next capacity-contract pull. To avoid waiting
for the next full poll, the heartbeat response carries `capacity_fingerprint`;
the radius compares it each heartbeat and re-pulls the full contract when it
changes — so a disable/hide/limit lands on the next heartbeat.

## Adding a new provider service

Add the catalog service, then add its `service_key → gate` entry to
`PROVIDER_TO_GATE` in `app/services/provider_service_gate.py`. The completeness
test (`tests/test_provider_service_gate.py::test_mapping_covers_full_catalog`)
fails until the new key is mapped, so nothing silently bypasses the gate.
