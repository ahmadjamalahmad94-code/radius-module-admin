# HobeRadius WhatsApp Gateway — Architecture

> **Product name:** HobeRadius WhatsApp Gateway
> **Customer-facing (Arabic):** رسائل واتساب للمشتركين
> **Admin-facing (English):** WhatsApp Gateway
> **Status:** Phase 1 — customer-provided Meta Cloud API credentials.

This document is the canonical reference for the WhatsApp messaging feature across the
two HobeRadius services. It is written **before** the implementation so every commit in
the series can be checked against it.

---

## 1. Product model

HobeRadius lets a network owner (our "customer" / licensed operator) send WhatsApp
notifications to **their own internet subscribers** — OTP codes, expiry reminders, quota
warnings, maintenance notices, password-change alerts, and subscriber-portal links.

The messaging itself runs on the **official Meta WhatsApp Business Platform (Cloud API)**.
HobeRadius does **not** resell WhatsApp messages and is **not** (in Phase 1) a Meta BSP.

### Why each customer uses their own WhatsApp Business number
- WhatsApp business-initiated messaging is tied to a verified **WhatsApp Business Account
  (WABA)** and a **phone number** that belongs to the sender. Sharing one number across
  many unrelated businesses violates Meta policy and risks a global ban that would take
  down every tenant at once.
- Per-tenant numbers give each operator their own quality rating, messaging-limit tier,
  template approvals, and branding (their business display name on the message).
- Isolation: one operator's rate limits, template rejections, or policy strikes never
  affect another.

### Why the customer pays Meta directly
- Meta bills the **WABA owner** for conversations/messages. The customer holds the WABA,
  so Meta charges the customer. HobeRadius never touches Meta billing and never fronts
  message costs.
- This keeps HobeRadius out of payment-reseller and money-transmission complexity, and
  keeps the cost model transparent to the operator.

### What HobeRadius charges for (the management layer)
- One-click-feeling **setup** of the Meta Cloud connection (guided wizard).
- **Subscriber-notification automation** wired to real RADIUS events.
- **Template** management and mapping.
- **Sending logs**, **delivery / read tracking**, **retries**, **rate limits**.
- **Service-plan limits** (daily/monthly/per-minute) and **opt-in control**.
- Operational **campaigns** (utility) and **integration** with the RADIUS server.

Billing for the management layer reuses the existing entitlement/plan machinery
(`service_catalog` + `CustomerServiceEntitlement`), service key **`whatsapp_gateway`**,
plan codes **`whatsapp_basic` / `whatsapp_pro` / `whatsapp_business`**.

---

## 2. Two-service architecture

```
            ┌─────────────────────────── radius-module-admin (PANEL) ───────────────────────────┐
            │  Central WhatsApp Gateway + SaaS control plane. Holds Meta tokens (encrypted).      │
            │                                                                                     │
 Subscriber │   Admin UI ───┐                                                                     │
   phone    │   Portal  ────┤  whatsapp services:                                                 │
   ▲        │   wizard      │   providers (Meta Cloud)  ── the ONLY code that calls Meta ──► Graph │──► Meta Cloud API
   │        │               │   crypto (Fernet)  phone  policy  queue  worker  webhook  settings   │      (graph.facebook.com)
   │        │   signed APIs ◄┼── /api/integration/hoberadius/whatsapp/*  (HMAC, per-license)        │◄── Webhook (status/inbound)
   │        │               │   message queue (idempotent) ── drain CLI (systemd timer) ──► send    │
   └────────┼───────────────┘                                                                     │
            └──────────────────────────────────────▲──────────────────────────────────────────────┘
                                                    │  signed bridge (existing HMAC + per-license secret)
            ┌───────────────────────────────────────┴─────────────── radius-module (CLIENT) ───────┐
            │  Lightweight. NO Meta tokens, NO direct Meta calls. Only enqueues via the bridge.      │
            │  AdminPanelClient.{get_whatsapp_status, enqueue_whatsapp_message, send_whatsapp_test,  │
            │                    sync_subscriber_preferences, get_message_status}                    │
            │  Event hooks: OTP (accounts_create), password reset (accounts_reset_pw),               │
            │               expiry/near-expiry/quota (dunning_worker), maintenance (tools).          │
            │  /admin/radius/whatsapp page: status + per-event toggles + test (no credentials).      │
            └─────────────────────────────────────────────────────────────────────────────────────┘
```

**Hard separation:**
- **Panel** = the gateway. It is the *only* place that stores Meta credentials and the
  *only* place that talks to `graph.facebook.com`.
- **Client** = a thin caller. It enqueues messages over the existing signed bridge and
  never sees a token. A WhatsApp failure must never break a RADIUS auth/accounting flow.

---

## 3. Data model summary (panel)

Seven tables (SQLAlchemy ORM in `app/models.py`, created by `db.create_all()`, patched on
live DBs by `ensure_schema_compatibility()` — no Alembic).

| Table | Purpose | Key columns |
|---|---|---|
| `whatsapp_tenant_accounts` | One Meta Cloud connection per customer | `customer_id`(uniq), `phone_number_id`, `waba_id`, `display_phone`, `access_token_enc`, `verify_token_enc`, `app_secret_enc`, `connection_status`, `last_error` |
| `whatsapp_service_settings` | Enable flag + limits + policy | `customer_id`(uniq), `enabled`, `daily_limit`, `monthly_limit`, `per_minute_limit`, `quiet_hours_*`, `require_opt_in`, `tz` |
| `whatsapp_templates` | Local→Meta template mapping + approval state | `customer_id`, `name`, `language`, `category`, `body`, `variables_json`, `meta_status`, uniq`(customer_id,name,language)` |
| `whatsapp_message_queue` | Source of truth for outbound + retry + delivery | `customer_id`, `idempotency_key`(uniq), `to_phone`, `template_name`, `payload_json`, `status`, `attempts`, `max_attempts`, `next_attempt_at`, `provider_message_id`, `last_error`, `event_type` |
| `whatsapp_webhook_events` | Raw inbound Meta events (audit + reconcile) | `event_id`(uniq), `event_type`, `payload_json`, `processed`, links to queue via `provider_message_id` |
| `whatsapp_subscriber_preferences` | Per-subscriber opt-in | `customer_id`, `subscriber_ref`, `phone_e164`, `opted_in`, `blocked`, uniq`(customer_id,subscriber_ref)` |
| `whatsapp_usage_counters` | Daily/monthly counters for limits + reports | `customer_id`, `window_type`, `window_key`, `sent_count`, `failed_count`, uniq`(customer_id,window_type,window_key)` |

Access tokens are **never** stored in plaintext (see §5) and **never** leave the panel.

---

## 4. Sending pipeline

1. **Enqueue** — the client (or admin/portal) calls the signed enqueue API with a stable
   `idempotency_key`. `queue.enqueue()` upserts on that key, so a duplicate request returns
   the existing row and never produces a duplicate WhatsApp message.
2. **Policy** — before a row is accepted, `policy.can_send()` checks: service enabled,
   account connected, event allowed by plan, daily/monthly/per-minute limits, quiet hours,
   subscriber opt-in, template exists + approved, phone valid. A block returns a
   machine-readable reason with an Arabic message.
3. **Drain** — `worker.drain_once()` (run by a systemd timer via `flask whatsapp-drain`,
   plus an opportunistic inline drain) atomically claims `queued → sending`, calls
   `MetaCloudWhatsAppProvider`, stores `provider_message_id`, marks `sent`, bumps counters.
   Transient failures retry with exponential backoff **1 / 5 / 15 min**, `max_attempts = 3`;
   non-transient failures fail immediately.
4. **Webhook** — Meta posts delivery/read/failed updates to the panel webhook endpoint;
   `webhook.process_event()` matches by `phone_number_id` + `provider_message_id` and
   updates the queue row (`delivered` / `read` / `failed`). Idempotent on Meta `event_id`.

---

## 5. Security model

- **No plaintext tokens.** `access_token`, `app_secret`, and `verify_token` are encrypted
  at rest with **Fernet** (`WHATSAPP_FERNET_KEY`). Helpers: `encrypt` / `decrypt` / `mask`.
- **No token in UI / API / logs.** Reads return only a masked preview (e.g. `EAAB…9xQ`).
  No serializer, template, API response, or log line emits a decrypted secret. Guard tests
  in both repos assert this.
- **HMAC on integration APIs.** Every `/api/integration/hoberadius/whatsapp/*` endpoint
  reuses the existing per-license signature + `X-HobeRadius-Admin-Secret` verification.
  Unsigned/bad-signature requests are rejected.
- **Webhook verification.** GET handshake validates the per-account `verify_token`; POST
  bodies are stored raw before processing and never crash the endpoint on unknown shapes.
- **Customer isolation.** Every query is scoped by `customer_id` (resolved from the signed
  license for client calls, from the session for portal calls). The worker loads each
  message's own customer account, so one tenant's token can never be used for another.
- **Idempotency.** Unique `idempotency_key` + atomic status claim prevent duplicate sends
  under retries or concurrent drains (keep the timer single-instance).
- **Audit.** Credential save, service enable/disable, retry, cancel, suspend, and settings
  changes write `AuditLog` rows.
- **Client constraints.** `radius-module` stores no Meta secrets, never calls Meta, never
  logs phone numbers / bodies at INFO, and wraps every enqueue so a failure cannot raise
  into auth/accounting.

---

## 6. Setup guide (operator, Phase 1)

1. In **Meta for Developers**, create/select a Business app, add **WhatsApp**, and get:
   Meta Business ID, WhatsApp Business Account ID (WABA), Phone Number ID, the display
   phone number, and a (system-user) **access token**. The number must be a WhatsApp
   Business number that the operator owns.
2. In the HobeRadius **customer portal → رسائل واتساب للمشتركين**, run the wizard:
   1) أدخل بيانات Meta → 2) افحص الربط → 3) اربط القوالب → 4) أرسل رسالة تجربة →
   5) فعّل الإشعارات → 6) تم التفعيل.
3. The operator pays Meta directly for usage. HobeRadius bills only for the management
   plan (`whatsapp_basic/pro/business`).

The service is **locked** until an admin grants the `whatsapp_gateway` entitlement.

---

## 7. Webhook setup guide

1. In the Meta app's **WhatsApp → Configuration → Webhook**, set the callback URL to the
   panel's WhatsApp webhook endpoint and the **Verify Token** to the value shown for the
   account in the panel (stored encrypted; compared on the GET handshake).
2. Subscribe to the `messages` field (delivery/read/status + inbound).
3. Meta sends a GET challenge → the panel echoes `hub.challenge` only when the verify token
   matches. After that, POST events flow in and reconcile message status.
4. App-secret signature validation on POST is supported via `app_secret_enc`.

---

## 8. Limitations (Phase 1)

- HobeRadius is **not** an official Meta BSP; no Embedded Signup yet. Credentials are
  entered manually by the operator.
- Business-initiated messages must use **approved templates**; template approval happens in
  Meta Business Manager (the panel stores/display `meta_status`, it does not auto-approve).
- One Meta Cloud account per customer in Phase 1 (multi-number is a future extension).
- The drainer is a timer-driven oneshot (panel has no resident worker); near-real-time, not
  instant. An inline best-effort drain reduces latency for interactive sends.
- Marketing messages are disabled by default; opt-in is required for non-OTP notices.

---

## 9. Future path — Embedded Signup / Meta Partner

When HobeRadius obtains Tech-Provider / Solution-Partner status, the manual-credential step
can be replaced by **Embedded Signup** (operators connect their WABA via an OAuth-style flow
without copying tokens). The data model already isolates per-customer accounts, so this is an
additive change to the connection step only — the queue, worker, policy, webhook, and client
bridge remain unchanged. Until that approval exists, the UI must not claim BSP status.

---

## 10. What requires real Meta credentials vs. what is mock-testable

**Needs real Meta creds (cannot be proven end-to-end with mocks):** live message delivery,
credential validation against Graph, real template approval status, and real inbound webhook
receipt (signature + verify-token handshake against a configured Meta app + public HTTPS).

**Fully mock-testable (no Meta needed):** all 7 tables, crypto round-trip + masking, phone
normalization, every policy gate, queue idempotency + status machine, worker backoff /
atomic-claim / max-attempts, webhook idempotency + challenge echo + status mapping (synthetic
payloads), all signed APIs (sign/verify/HTTPS/isolation), entitlement catalog, both UIs, the
portal wizard, the client bridge signing, and client event-wiring + failure-isolation.

The provider is mocked in tests; **a successful live Meta connection is never faked.**
