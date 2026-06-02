# WhatsApp Embedded Signup (Meta) — self-service onboarding

Replaces the manual "paste your Meta token/IDs" onboarding with Meta's official
**Embedded Signup**: the customer clicks one button, logs into Facebook, picks
their WhatsApp number, approves permissions, and returns connected — no token
hunting, no Business Manager maze.

## Where it lives (architecture)

WhatsApp is centralized in the **license panel** (`radius-module-admin`):

- `radius-module` (the RADIUS app) is a **thin client** — it never stores Meta
  secrets; it enqueues messages to the panel over the signed bridge.
- The panel owns the per-customer connection (`whatsapp_tenant_accounts`,
  Fernet-encrypted token), the Meta Cloud API provider, templates, the message
  queue/worker, and the inbound webhook.

Embedded Signup therefore lives in the panel's **customer portal**
(`/portal` → WhatsApp pane), mirroring the existing Google Drive OAuth flow, and
feeds the **same** `whatsapp_tenant_accounts` storage + `MetaCloudWhatsAppProvider`.
One source of truth; the bridge and send path are unchanged.

## Components

| Layer | File |
|---|---|
| Schema (additive) | `app/models.py` → `WhatsAppTenantAccount.{onboarding_method,scopes,last_sync_at}`; ALTER in `app/__init__.py:ensure_schema_compatibility` |
| Config (env, flag-gated) | `app/config.py` → `META_*` |
| Service | `app/services/whatsapp/embedded_signup.py` |
| Routes | `app/public/routes.py` → `POST /portal/whatsapp/embedded/complete`, `action=disconnect` |
| Frontend | `app/templates/public/customer_portal_dashboard.html` (WhatsApp pane) |
| Provider (reused) | `app/services/whatsapp/providers.py` |
| Webhook (reused + hardened) | `app/services/whatsapp/webhook.py`, route `/api/whatsapp/webhook` |
| Tests | `tests/test_whatsapp_embedded_signup.py` (19) |

## Flow

1. Browser loads the Meta JS SDK and calls
   `FB.login({config_id, response_type:'code', override_default_response_type})`.
2. The popup returns an authorization `code`; a `WA_EMBEDDED_SIGNUP` message
   event carries the selected `waba_id` + `phone_number_id`.
3. The page POSTs `{code, waba_id, phone_number_id}` (JSON, CSRF header) to
   `/portal/whatsapp/embedded/complete`.
4. `embedded_signup.complete_signup()` (server): exchange code → access token →
   read scopes (`/debug_token`) → fetch phone + WABA metadata → subscribe the app
   to the WABA (so webhooks flow) → persist via `wa_settings.upsert_account()`
   (token **encrypted**) → mark `connection_status='connected'`,
   `onboarding_method='embedded'`; audited.
5. The pane refreshes → **✅ واتساب متصل** with name/number/date + actions
   (test message / reconnect / disconnect).

## Prerequisites (you provide)

A Meta App configured as a **WhatsApp Tech Provider** with an **Embedded Signup
configuration**, in Live mode, with `whatsapp_business_management` +
`whatsapp_business_messaging`. Then set (env only — never commit):

```
META_EMBEDDED_SIGNUP_ENABLED=1
META_APP_ID=<your app id>
META_APP_SECRET=<your app secret>
META_CONFIG_ID=<your embedded-signup config id>
META_GRAPH_VERSION=v21.0
```

Also configure the Meta App's webhook callback URL to
`https://<panel-host>/api/whatsapp/webhook` and verify-token as you prefer; the
panel verifies inbound POSTs with the **app secret** (`X-Hub-Signature-256`).

Until `META_APP_ID`/`META_CONFIG_ID` are set (or the flag is `0`), the embedded
CTA is **hidden** and the manual "advanced" path is shown — nothing breaks.

## Backward compatibility & rollback

- The manual credential path is fully preserved under «إعداد متقدم» (collapsible);
  its route action `save_credentials` + `validate` are unchanged.
- Schema changes are additive, nullable columns (existing rows = `manual`).
- **Rollback** = set `META_EMBEDDED_SIGNUP_ENABLED=0` (CTA disappears, manual
  path remains). The added columns are harmless if left in place.

## Security

- Tokens encrypted at rest (Fernet, `WHATSAPP_FERNET_KEY`); never logged, never
  returned to the browser, never in exception text.
- All actions scoped to the **session customer** — a `customer_id` in the body
  is ignored (no cross-tenant leakage).
- `whatsapp_gateway` entitlement required; CSRF enforced; every connect /
  disconnect / error is audited.
- Webhook POSTs verified against the app secret (constant-time).
