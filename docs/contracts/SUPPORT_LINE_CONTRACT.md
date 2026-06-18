# Support-line contract (customer radius ↔ provider licensing panel)

The bidirectional technical-support line over the pull-based bridge. All
endpoints are `POST`, under `/api/integration/hoberadius/`, and carry the same
guard triad as every bridge call: **HTTPS required** (426), **bearer = license
key** in the JSON body (401/403), customer resolved from the license.

## Channels

| channel | direction | status | endpoints |
|---|---|---|---|
| **Tickets** | both | ✅ EXISTS | create + thread-pull/reply |
| **Chat** (poll-based) | both | ✅ EXISTS | messages/send + messages/poll |
| **Activations** | both | ✅ EXISTS | service-requests + capacity-contract |
| **Provider→customer notices** | P→C | ✅ EXISTS | messages/poll + messages/ack |

Chat is **poll-based** (no websocket): the radius pulls `messages/poll` on its
heartbeat cadence, so it's near-real-time, not instant. That's the right fit for
the pull-based bridge.

## 1. Tickets / support

### Create (radius → provider)
`POST service-requests`
```jsonc
{ "license_key": "HBR-…", "service_key": "customer_support",
  "request_type": "support", "notes": "…", "desired_limits": {} }
→ 201 { "ok": true, "status": "pending",
        "service_request": { "id", "reference": "SR-…", "title", "service_key",
                             "request_type", "status" } }
```

### Thread pull + customer reply (both directions) — NEW
`POST service-requests/messages`
```jsonc
{ "license_key": "HBR-…", "reference": "SR-…",
  "message": "optional customer reply onto the thread" }
→ 200 { "ok": true,
        "service_request": { "id", "reference", "title", "service_key", "status" },
        "messages": [ { "id", "sender": "admin|customer|system",
                        "event", "body", "created_at" }, … ] }   // visible (non-internal) only
```
The provider replies from the admin panel (`POST /admin/service-requests/<id>/reply`);
those replies appear in this pull so they reach the customer's radius panel.
Unknown `reference` → 404.

## 2. Chat + 4. Provider→customer notices (shared `panel_messages` line) — NEW

One `PanelMessage` table backs both. `direction` = `to_customer` | `from_customer`;
`channel` = `notice` | `chat`; `importance` = `info` | `warning` | `critical`.

### Provider → customer pull
`POST messages/poll`
```jsonc
{ "license_key": "HBR-…" }
→ 200 { "ok": true, "count": N,
        "messages": [ { "id", "direction": "to_customer", "channel", "importance",
                        "subject", "body", "sender_label", "created_at" }, … ] }
```
Returns only rows not yet delivered, oldest-first, and **stamps them delivered**
so the next poll is clean. The provider composes from
`GET/POST /admin/customers/<id>/messages`.

### Ack seen (radius → provider)
`POST messages/ack`  → `{ "license_key", "message_ids": [1,2,3] }` → `{ "ok": true, "acked": K }`
Marks the customer saw them (panel shows سُلّمت → شوهدت).

### Customer → provider (chat / support)
`POST messages/send`
```jsonc
{ "license_key": "HBR-…", "channel": "chat", "subject": "", "body": "…" }
→ 201 { "ok": true, "status": "received", "message_id": N }
```
Lands in the provider inbox (the customer's panel-message thread). Empty body → 422.
Requires an **active** license (403 otherwise).

## 3. Activations (the unlock loop)

`POST service-requests` (`request_type: "activation"`, optional `desired_limits`)
→ lands in the provider «طلبات الخدمات» queue → admin approves
(`POST /admin/service-requests/<id>/approve`, or `/trial`) → entitlement granted →
flows into the **capacity contract** (`POST capacity-contract`) under
`services.<key>` + `provider_grants`. Examples:
- IP-change → `desired_limits.quota_gb` → `services.ip_change_vpn.traffic_quota_gb`.
- SMS package → `desired_limits.package_messages` → credited to
  `services.sms_gateway.limits.sms_package_credits` (additive).
- Generic «طلب تفعيل» → the service flips `enabled: true` / `status: active`.

## Provider-side routes (admin panel)

| route | purpose |
|---|---|
| `GET  /admin/service-requests` + `/<id>` | tickets/activations inbox + detail |
| `POST /admin/service-requests/<id>/reply` | reply on a ticket thread |
| `POST /admin/service-requests/<id>/approve` `/trial` | approve an activation |
| `GET  /admin/customers/<id>/messages` | panel-message thread (notices + chat) |
| `POST /admin/customers/<id>/messages` | send a notice / chat reply to the radius |

## Models / services (provider side)

- `PanelMessage` (`app/models.py`) — the support-line message row.
- `app/services/panel_messaging.py` — `send_to_customer`, `record_from_customer`,
  `poll_undelivered`, `ack_seen`, `thread_for_customer`, `unread_from_customer_count`,
  `mark_inbound_seen`, `to_bridge_dict`.
- `CustomerServiceRequest` + `CustomerServiceRequestMessage` — tickets/activations.
- Bridge handlers in `app/api/routes.py`.

## What the radius side must add

1. Poll `messages/poll` on the heartbeat; render notices (respect `importance`)
   and chat in the customer's panel; `messages/ack` the ids shown.
2. A chat composer that `POST messages/send` (`channel: "chat"`).
3. On a ticket, pull `service-requests/messages` to show the provider's replies
   and `POST` the customer's reply via the same endpoint (`message` field).
4. Activations already covered by the capacity-contract pull.
