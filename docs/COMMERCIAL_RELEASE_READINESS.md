# Commercial release readiness — provider/licensing panel

**Date:** 2026-06-18 · **Branch:** `test/commercial-release-readiness` · **Scope:**
the provider (licensing-panel) side of the RADIUS-as-a-service product and the
capacity/contract it emits to the customer radius over the bridge.

**Verdict: READY on the provider side**, with the explicit caveats in §6. Every
commercial scenario the owner listed is implemented and covered by automated
tests. Two items are intentional non-blockers (poll-based chat; live 187.x
browser verify pending the owner's redeploy).

---

## 1. Test inventory (commercial scenarios)

All green: **102 passed** across the commercial suites (run together, isolated DB).

| suite | tests | covers |
|---|---:|---|
| `test_commercial_e2e.py` | 22 | end-to-end through the bridge: lifecycle, packages, discounts, 5 gate states, activations, الجهات, support line |
| `test_subscription_packages.py` | 10 | 6 packages, idempotent seed, discount engine, capacity→contract |
| `test_sms_hybrid.py` | 7 | SMS BYO-free + paid package-credit (additive) |
| `test_multi_tenant_hidden.py` | 5 | «الجهات» hidden-until-granted + grant |
| `test_hide_declutter.py` | 4 | «إخفاء للترتيب» vs «موقوفة» commercial block |
| `test_support_line.py` | 9 | tickets/chat/notices/activations round-trips |
| `test_provider_service_gate.py` | 17 | 45→14 gate map, aggregation, license block, paid→locked_upgrade |
| `test_ipchange_traffic_request.py` | 6 | IP-change «طلب تفعيل»-with-traffic |
| `test_trial_plan.py` | 8 | 14-day trial, free/paid split, caps |

> Note: a separate set of ~27 pre-existing failures in unrelated suites
> (`test_security_and_validation`, some `test_customer_control_layer`,
> `test_whatsapp_*`) fail identically on clean `main` (verified at `a7d7c30`).
> They are environmental (prod-secret/rate-limiter config + an Arabic-literal
> encoding mismatch on this Windows runner) and are **out of scope** for the
> commercial model — none touch the commercial code paths.

---

## 2. Scenario checklist (pass / gap)

### License lifecycle
| state | contract result | status | proof |
|---|---|---|---|
| never-activated (no/unknown license) | 401 at bridge; `license.activated=false` | ✅ | `test_lifecycle_never_activated` |
| pending customer (not yet activated by admin) | 403 `reason=customer_pending` | ✅ | `test_lifecycle_pending_customer_blocked` |
| active | `active=true, status=active` | ✅ | `test_lifecycle_active` |
| expired (past grace) | `active=false, status=expired` | ✅ | `test_lifecycle_expired_past_grace` |
| grace / outage | `active=true, status=grace` | ✅ | `test_lifecycle_in_grace` |
| suspended / revoked | `active=false` (denied) | ✅ | `test_lifecycle_suspended_denied` |
| trial 14-day | `active_online.max=100`, 14d term | ✅ | `test_trial_emits_100_concurrent_and_14_days` |

### Packages, pricing, discounts
| item | status | proof |
|---|---|---|
| each package emits its concurrency cap (50/100/250/500/1000/0) | ✅ | `test_each_package_emits_its_concurrency_cap` (parametrized ×6) |
| capacity = `limits.active_online.max` (instance-wide, all session types) | ✅ | e2e + `test_package_capacity_is_max_active_in_contract` |
| duration discounts compute (3/6/12mo) | ✅ | `test_discounts_compute_default_and_editable`, `test_default_discounts_and_quote` |
| admin edits prices / caps (Plans) | ✅ | `test_ensure_idempotent_no_clobber` (seed never clobbers edits) |
| admin edits discount tiers (add/remove/%/enable) | ✅ | `test_discounts_are_editable`, `test_discount_save_route` |

### Service-gate states (each → correct contract field)
| state | contract | status | proof |
|---|---|---|---|
| free / enabled | `services.<k>.enabled=true`; grant `active` | ✅ | `test_gate_state_free_enabled` |
| locked_upgrade (paid, visible «طلب تفعيل») | grant `status=locked_upgrade, requires_activation=true` | ✅ | `test_gate_state_locked_upgrade` |
| disabled (موقوفة, hard block) | grant `status=disabled` (radius hide+403) | ✅ | `test_gate_state_disabled_commercial_block` |
| hidden (إخفاء للترتيب) | `hidden=true` + `enabled=true` (no 403) | ✅ | `test_gate_state_hidden_declutter` |
| hidden_until_granted (الجهات) | `visibility=hidden, status=hidden, upgradable=false` | ✅ | `test_gate_state_hidden_until_granted` |

### Activations
| item | status | proof |
|---|---|---|
| «طلب تفعيل» (bridge) → provider queue → approve → contract | ✅ | `test_activation_loop_through_bridge` |
| IP-change traffic amount flows to `services.ip_change_vpn.traffic_quota_gb` | ✅ | `test_approve_with_requested_quota_flows_to_contract` |
| SMS package size → credited `sms_package_credits` (additive) | ✅ | `test_approve_package_credits_sms_balance`, `test_second_package_is_additive_not_clobbered` |

### Support line (bidirectional)
| channel | status | proof |
|---|---|---|
| tickets create + provider reply pull + customer reply | ✅ | `test_ticket_create_then_provider_reply_reaches_radius`, `test_customer_reply_over_bridge_lands_on_thread` |
| chat (poll-based) both directions | ✅ (poll, not websocket — see §6) | `test_customer_chat_message_lands_in_provider_inbox`, e2e poll |
| provider→customer notices (poll + ack) | ✅ | `test_provider_notice_is_pulled_and_acked` |
| admin composer + thread render | ✅ | `test_admin_can_send_and_view_thread` |

### «الجهات» grant
| item | status | proof |
|---|---|---|
| grant emits `entity_count` + `per_entity_limits` | ✅ | `test_entities_grant_emits_into_contract` |
| revoke hides again (reversible) | ✅ | `test_granted_then_revoked_hides_again` |
| stays hidden in trial | ✅ | `test_hidden_even_in_trial` |

---

## 3. Contract field cross-reference (agree with radius)

Source of truth: `docs/contracts/PROVIDER_SERVICE_GATE_MAP.md` +
`docs/contracts/SUPPORT_LINE_CONTRACT.md`.

| concept | contract field | radius must |
|---|---|---|
| concurrent-online ceiling | `limits.active_online.max` (`scope=instance`, `counts=all_session_types`; 0=∞) | count live sessions across cards+subscribers+PPPoE+hotspot; refuse new online sessions at the cap |
| back-compat cap | `limits.subscribers.max_active` / `max_total` | mirror of the above for older builds; new builds read `active_online` |
| commercial block | `provider_grants.<gate>.status="disabled"` | hide + 403 |
| declutter hide | `services.<k>.hidden=true` (status stays active) | remove from the customer-panel nav, **no 403**, reversible |
| paid upsell | `provider_grants.<gate>.status="locked_upgrade"`, `requires_activation=true` | show locked + «طلب تفعيل/ترقية» CTA |
| hidden-until-granted | `services.multi_tenant.visibility` = `hidden`\|`granted` (+`entity_count`,`per_entity_limits`) | render nothing while hidden; on granted, enable N tenants with per-entity caps |
| SMS package credit | `services.sms_gateway.limits.sms_package_credits` | enforce remaining paid-SMS balance |
| support line | `POST .../service-requests/messages`, `.../messages/poll`, `.../messages/send`, `.../messages/ack` | poll on heartbeat; render notices/chat; ack; post replies |

---

## 4. Admin surfaces (provider operability)

- `/admin/packages` — pricing preview (concurrent-online framing + discount badges).
- `/admin/discounts` — editable duration-discount tiers.
- `/admin/plans` — edit package prices/caps.
- `/admin/customers/<id>/service-tiers` — per-customer tier, hide-for-declutter
  vs موقوفة block, «الجهات» grant.
- `/admin/customers/<id>/messages` — support-line thread + composer.
- `/admin/customers/<id>/assign-package` — assign a package + term.
- `/admin/service-requests` + `/<id>` — activations/tickets queue + reply/approve.

---

## 5. What the radius side still needs to implement (consumer side)

These are **radius-side** tasks (this panel already emits everything):
1. Enforce `limits.active_online.max` as the global concurrent-online ceiling.
2. Honor `services.<k>.hidden` as nav-declutter (no 403) vs `provider_grants` `disabled` (403).
3. Render `multi_tenant.visibility` (nothing when hidden; N tenants when granted).
4. Poll the support-line endpoints on the heartbeat; render notices + chat; ack.
5. Pull `service-requests/messages` for ticket replies; post customer replies.

---

## 6. Remaining gaps / non-blockers before launch

| item | severity | note |
|---|---|---|
| Live chat is **poll-based**, not websocket | low | adequate for the pull-based bridge; near-real-time on heartbeat cadence. A true realtime channel would need websocket/SSE infra — defer unless the owner requires instant chat. |
| No **broadcast-to-all-customers** notice | low | `send_to_customer` is per-customer; a fan-out loop/admin bulk page can be added later. |
| Live verify on customer radius **187.x** | tracked | the customer instance is license-locked pending the owner's redeploy; the code-level audit + fixes are complete and tested. Browser round-trip to be confirmed post-redeploy. |
| ~27 pre-existing unrelated test failures | none (out of scope) | identical on clean `main`; environmental (prod-config/rate-limit/encoding), not commercial code. |

**Bottom line:** the commercial model — trial, six packages with concurrent-online
caps, configurable discounts, the five gate states, activations, the «الجهات»
grant, and a bidirectional support line — is implemented, contract-coordinated
with the radius, and covered by 102 passing automated tests. Cleared for
commercial release on the provider side, pending the 187.x live confirmation.
