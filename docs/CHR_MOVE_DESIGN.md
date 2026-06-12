# «نقل الـCHR / تغيير الـIP العام» — design

Re-home a customer's RADIUS realm + its live sessions from one CHR to
another so the customer's egress public IP changes — without provisioning
multiple public IPs on a single CHR.

## §1. Mechanism in one diagram

```
   [panel UI]                                  ╭─ panel writes routing change ─╮
       │                                       │                                │
       │  super_admin POST                     ▼                                ▼
       │  /admin/customers/<id>/move-chr    ProxyRealmRoute.                CustomerRadiusInstance
       │                                    allowed_fleet_chr_node_ids      .last_published_fingerprint
       │                                    = [target_node.id]              (refreshed → proxy notices)
       │
       │  HMAC-signed call                    ╭─ proxy → RADIUS CoA ──────────╮
       │  POST /api/proxy/coa/disconnect ──→  │                                │
       │  { realm: "client5",                  ▼                                ▼
       │    reason: "panel:chr-move" }      Disconnect-Request          live session drops →
       │                                    UDP 3799 → CHR              reconnect on TARGET CHR
       │
       └─ result: { ok, old_public_ips, new_public_ip, coa_status }
                  audit("chr_move_executed", …)
```

## §2. Which path applies — VPN end-user vs the customer-NAS «رابط RADIUS»

| Traffic class | What pins it to a CHR today | What changes for the move |
|---|---|---|
| **End-user VPN** (PPTP/SSTP/L2TP/IPsec/WG-users) terminating on a CHR | The CHR the customer's user dials in to is the one the panel routing-table lets the proxy route RADIUS to (`ProxyRealmRoute.allowed_fleet_chr_node_ids`). | Update `allowed_fleet_chr_node_ids` to `[target.id]`; CoA-Disconnect against the realm; on reconnect, proxy re-authenticates against new CHR. End-user public IP changes — egress is now `target_node.public_ip`. |
| **Customer-NAS «رابط RADIUS» SSTP** — customer's MikroTik dialing into the CHR's same SSTP listener to upstream RADIUS | Same path. Both end-users AND the customer NAS authenticate as RADIUS users against the same SSTP listener (see `feat/chr-unified-provisioning-complete`'s «RADIUS link via same listener» note). | Customer NAS reconnects on the new CHR after CoA-Disconnect. Same RADIUS user; **same shared pool means Framed-IP stays** — no client-side IP renumber on the customer's LAN. |

The wg-radius plane (panel↔proxy) is **unchanged** — that's the control
plane between the panel and the central proxy, orthogonal to which CHR
egresses customer traffic.

## §3. Routing change — exact

Per customer the change is two writes inside a single transaction:

1. For every `ProxyRealmRoute` owned by `CustomerRadiusInstance` of the
   customer: set `allowed_fleet_chr_node_ids_json = json([target.id])`.
2. Refresh `CustomerRadiusInstance.last_published_fingerprint` so the
   `/api/proxy/routing-table` reconciler picks up the change on its next
   poll. The proxy's existing config-drift detection (§6.4 in
   `CUSTOMER_RADIUS_TUNNEL_DESIGN.md`) handles the rest.

The panel never touches the CHR directly — the central proxy is the
single source of truth + the single emission point.

## §4. Reconnect mechanism — chosen path + rejected alternatives

| Option | What it does | Verdict |
|---|---|---|
| **A. Panel → Proxy (signed HTTP) → CHR (RADIUS CoA UDP 3799)** | Proxy already speaks CoA to CHRs and tracks live (realm, NAS) state. Panel emits one signed POST. | **Selected.** |
| B. Panel → CHR directly (RADIUS CoA UDP 3799) | Panel would need each NAS-IP + the central CHR shared secret — leaks central credentials, violates `chr-creds-must-stay-central`. | Rejected. |
| C. Panel → Bridge → customer's local RADIUS → NAS Disconnect-Request | Customer-controlled link; reconnect intent shouldn't depend on the customer's bridge being up. | Rejected. |

**Panel-side contract** (built in this branch):

```http
POST <proxy>/api/proxy/coa/disconnect
X-Proxy-Token: <ts>:<nonce>:<hmac>
Content-Type: application/json

{ "realm": "client5",
  "reason": "panel:chr-move",
  "target_node_id": 12 }
```

The proxy-side handler is a **build-deferred surface** owned by the
proxy repo. Until it ships, the panel:
- emits the call best-effort,
- records the attempt in audit + result,
- returns `coa_status="pending_proxy_endpoint"` so the UI says
  «موجَّه — في انتظار قبول الوكيل» rather than a misleading green check.

The routing update is durable independent of the CoA outcome.

## §5. Idempotency + safety

| Concern | Behaviour |
|---|---|
| Who can trigger | `@super_admin_required` only. CSRF-protected POST. |
| Pre-flight | Target must be in `fleet_node_router.available_nodes()` (enabled + not drain + status != disabled) AND have ≥ 1 `vpn_*` role enabled. Otherwise refused with a precise Arabic message. |
| Same-CHR move | No-op success: routing already points at target → nothing to write. CoA still emitted (forces reconnect, useful for the «خلِّيه يعيد الاتصال على نفس العقدة» case). |
| CoA failure | Routing update **NOT** rolled back. Move is durable; owner can re-CoA from the same button. |
| Confirmation | Design-system modal — **never** native `alert/confirm`. Surfaces `current_public_ips → target.public_ip`, target name, roles, CoA fallback message. |
| Audit | `chr_move_executed` row with `{customer_id, from_node_ids, to_node_id, coa_status, http_status}`. |

## §6. Scope — built here vs deploy-only

| | Built here (panel) | Deploy-only |
|---|---|---|
| Routing-table update for the customer's realm | ✓ | — |
| Signed CoA-Disconnect HTTP POST emission | ✓ | — |
| Customer detail UI button + modal old→new IP | ✓ | — |
| Eligibility refusal (down / disabled / drain / no VPN roles) | ✓ | — |
| Idempotency (same-CHR no-op, durable on CoA failure) | ✓ | — |
| Audit row capturing actor + from/to + CoA outcome | ✓ | — |
| Proxy endpoint `POST /api/proxy/coa/disconnect` | — | ✓ Proxy repo |
| Actual RADIUS Disconnect-Request packet on the CHR | — | ✓ Proxy side |
| End-to-end live session reconnect on a real CHR | — | ✓ Owner verifies post-deploy |

## §7. Tests pinned in this branch

* `test_move_refuses_when_no_radius_instance` — surfaces "العميل لا يملك realm."
* `test_move_refuses_ineligible_target_down` / `_drain` / `_disabled` /
  `_no_vpn_roles` — each Arabic refusal message.
* `test_move_updates_route_allowed_node_ids` — exact write.
* `test_move_emits_coa_with_signed_header_and_payload` — emitter called
  with realm + reason + target_node_id; signature header present.
* `test_move_surfaces_old_and_new_public_ip` — result struct carries both.
* `test_move_is_idempotent_for_same_target` — second call = no-op success.
* `test_move_records_audit_row` — actor + from/to + coa_status persisted.
* `test_move_durable_when_coa_fails` — routing change persists; result
  reports `coa_status="failed"` or `"pending_proxy_endpoint"`.

End-to-end live reconnect against real CHRs is the owner's post-deploy
verification step.
