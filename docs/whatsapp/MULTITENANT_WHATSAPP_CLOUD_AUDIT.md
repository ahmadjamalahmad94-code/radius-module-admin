# Multi-Tenant WhatsApp Cloud API — Audit & Completion Report

**Repos:** `radius-module-admin` (the License Panel — owns the Meta connection) ·
`radius-module` (the runtime — a thin bridge client).
**Branch:** `feat/whatsapp-cloud-multitenant` · **Date:** 2026-06-29.
**Verdict:** the multi-tenant integration was **already built and well-engineered**
in the panel. This pass **audited** it end-to-end against the 10-point business
model, **closed two concrete gaps**, and produced UI screenshots + a green test run.

---

## Business model (as enforced in code)

Each tenant (`customer_id`) connects **their own** WhatsApp Business Account + phone
number and pays Meta directly. **One central Meta App** ("HobeRadius") brokers
Embedded Signup for everyone; each tenant's resulting WABA / phone / token is stored
**per-tenant, encrypted**. There is **no shared/global HobeRadius number** in the send
path — every send uses *that tenant's* `phone_number_id` + token.

> `tenant_id` in the panel = **`customer_id`** (FK `customers.id`). `license_id` is an
> optional secondary reference carried alongside.

---

## Audit — existing vs added

### Already existed (verified, not duplicated)

| # | Requirement | Where |
|---|-------------|-------|
| 1 | **Tenant-level settings** (per `customer_id`, not global) | 7 models, all `customer_id`-scoped: `WhatsAppTenantAccount`, `WhatsAppServiceSettings`, `WhatsAppTemplate`, `WhatsAppMessageQueue`, `WhatsAppWebhookEvent`, `WhatsAppSubscriberPreference`, `WhatsAppUsageCounter` (`app/models.py`) |
| 2 | **Embedded Signup** — central Meta app creds at provider level (from UI, not env), Connect button, code-exchange callback | Config: `app/services/whatsapp/embedded_settings.py` (App ID/Secret/Config ID/Graph version in `settings` table, App Secret Fernet-encrypted, env fallback). Flow: `embedded_signup.py` (`exchange_code` → `complete_signup`). Routes: `POST /portal/whatsapp/embedded/{config,start,complete}` (`app/public/routes.py`). UI launches `FB.login` with the configured `config_id`. |
| 3 | **Per-tenant encrypted storage** of `business_id`, `waba_id`, `phone_number_id`, `display_phone_number`, `access_token` (+expiry), webhook verify-token, connection status | `WhatsAppTenantAccount` (`models.py`). `access_token`/`webhook_secret` Fernet-encrypted; verify-token stored as a Werkzeug hash; secrets never returned (only `account_public_dict` masked previews). `settings.upsert_account`. |
| 4 | **Per-tenant send service** via Meta Graph API using *that tenant's* `phone_number_id` + token | `MetaCloudWhatsAppProvider.send_template_message` → `POST https://graph.facebook.com/v21.0/{tenant phone_number_id}/messages` (`providers.py`); worker resolves the tenant account by `customer_id` (`worker.py`). No global-number fallback. |
| 5 | **Webhook** — verify-token handshake + status receiver (sent/delivered/read/failed), updates logs | `app/services/whatsapp/webhook.py` (`verify_challenge`, idempotent `ingest`, `X-Hub-Signature-256` check, per-customer status mapping); route `GET/POST /api/whatsapp/webhook`. |
| 6 | **Message-logs table** (per tenant: to, template, status, timestamps, error, wa message id) | `WhatsAppMessageQueue` + `queue.py` (`enqueue`/`mark_sent`/`mark_delivered`/`mark_read`/`mark_failed`/`schedule_retry`). |
| 7/8 | **No hardcoded global number / no company-number send** | Confirmed: all sends parameterized by the tenant account; missing `phone_number_id` errors out, never falls back to a global number. The panel "house" creds (`cloud_settings.py`) are used **only** for the admin's own test connection / cloud-test, never to send a customer's messages. |
| 9 | **Credentials encrypted at rest, masked, never committed** | `crypto.py` (Fernet via `WHATSAPP_FERNET_KEY`, no ephemeral-key fallback), `mask_secret`, audited reveal. |
| 10 | **UI: Settings → WhatsApp, Connect/Status/Test, RBAC-gated, no native alerts** | Provider: `/admin/settings#whatsapp-cloud` + `#whatsapp-embedded`. Per-tenant: `/admin/customers/<id>/whatsapp`. Gateway: `/admin/whatsapp-gateway`. Portal self-service: `/portal/whatsapp` (Embedded Signup primary, manual Cloud-API paste fallback). |
| — | **Bridge endpoints** the runtime calls | `POST /api/integration/hoberadius/whatsapp/{status,messages/enqueue,messages/test,cloud-test,subscriber-preferences/sync,messages/status}` (`app/api/routes.py`), bearer-auth (license key) + HTTPS-guarded, per-customer isolated. |

### Added / fixed this pass

1. **Embedded Signup now persists token expiry.** `exchange_code` already returned
   Meta's `expires_in`, but `complete_signup` dropped it, so `token_expires_at` was
   never set for the embedded path — even though the **manual** admin path already
   stored it (`admin/routes.py`, with a date field in `customer_whatsapp.html`). Now
   captured into `WhatsAppTenantAccount.token_expires_at` (and cleared when Meta returns
   a non-expiring business token) + surfaced in `account_public_dict`. Closes spec req 3
   ("token_expiry / long-lived token metadata"). New test:
   `test_complete_signup_stores_token_expiry_when_meta_returns_expires_in`.

2. **Fixed a stale, contradictory test.** `test_bad_signature_request_is_rejected_401`
   sent a **valid** bearer `license_key` + a corrupt `signature` and expected `401`.
   Authentication migrated to **bearer-only** (`docs/SIMPLE_LINK_CONTRACT.md`):
   `verify_license_signature` authenticates on the license key and **ignores the
   signature**, so a valid key returns `200`. The sibling `test_unsigned` and both the
   fixture/`_signed` docstrings were already migrated; this one was missed. Repurposed to
   assert the real contract (`test_garbage_signature_is_ignored_in_bearer_mode`): a
   garbage signature is ignored with a valid key (not 401), but an unresolvable key is
   still rejected (401). **This was a stale test, not a code regression** — the
   bearer-only auth model is an existing, documented project decision.

---

## Decisions flagged (no `AskUserQuestion` — built to spec)

- **Central Meta-app config lives at the provider level in two places** that share the
  same `settings` keys + Fernet layer: the **Embedded Signup** card
  (`#whatsapp-embedded`, `embedded_settings.py`) and the **Cloud API house-creds** card
  (`#whatsapp-cloud`, `cloud_settings.py`). Both read DB → env → default. The *one*
  provider step the owner does **once**: enter **App ID / App Secret / Config ID** (and
  optionally Graph version) in Settings → WhatsApp. Per-tenant **Connect** is then
  self-service via the portal's Embedded Signup, or a manual Cloud-API paste fallback.
- **Webhook signature is Phase-1 lenient** (`webhook.py`): an event with no resolvable
  secret, or no `X-Hub-Signature-256` header, is trusted; a present secret + present
  header must match (constant-time). Intentional per the module docstring; flagged for a
  later "strict" upgrade.
- **The owner's test values** (`phone_number_id 1169165929613113`, `waba_id
  27438053492514303`) are entered via UI for his test tenant; they are **never
  hardcoded** in app code. They appear only in the throwaway render seed
  (`scripts/render_whatsapp_ui.py`) for the screenshots.
- **`radius-module` (runtime) needs no change.** It is a thin bridge client (Path A in
  its own `WHATSAPP_AUDIT_REPORT.md`): it stores no Meta creds, calls the 6 bridge
  endpoints with its license key, and the panel now owns the full Cloud API. The prior
  report's P0 gate ("are the 6 panel endpoints implemented?") is **verified resolved**.

---

## Verification

- WhatsApp/embedded/cloud suite: **259 passed** (`pytest -k "whatsapp or embedded or cloud_init"`).
- UI screenshots (regenerated by `scripts/render_whatsapp_ui.py`): `_wa_shots/`
  - `_shot_settings_whatsapp.png` — provider Settings: Cloud API + Embedded Signup cards (secrets masked, "إظهار مؤقت").
  - `_shot_customer_whatsapp.png` — per-tenant control: connected account, plan/limits, approved templates, test-message, message log, webhook events.
  - `_shot_whatsapp_gateway.png` — global gateway dashboard (per-customer KPIs).
