# WhatsApp Embedded Signup (Meta) — self-service onboarding

Replaces the manual "paste your Meta token/IDs" onboarding with Meta's official
**Embedded Signup**: the customer clicks one button, logs into Facebook, picks
their WhatsApp number, approves permissions, and returns connected — no token
hunting, no Business Manager maze.

## Where it lives (architecture)

WhatsApp is centralized in the **license panel** (`radius-module-admin`):

- `radius-module` (the RADIUS app) is a **thin client** — it never stores Meta
  secrets; it reads status and enqueues messages over the existing signed HMAC
  bridge, and deep-links the operator to the panel to manage the connection.
- The panel owns the per-customer connection (`whatsapp_tenant_accounts`,
  Fernet-encrypted token), the Meta Cloud API provider, templates, the message
  queue/worker, and the inbound webhook.

Embedded Signup lives in the panel's **customer portal** (`/portal` → WhatsApp
pane) and feeds the **same** `whatsapp_tenant_accounts` storage +
`MetaCloudWhatsAppProvider`. One source of truth; the bridge/send path unchanged.

## Components

| Layer | File |
|---|---|
| Schema (additive) | `app/models.py` → `WhatsAppEmbeddedSignupAttempt` (state/nonce sessions) + `WhatsAppTenantAccount.{onboarding_method,scopes,last_sync_at}`; create_all + `app/__init__.py:ensure_schema_compatibility` |
| Config (env, flag-gated) | `app/config.py` → `META_*`, `WHATSAPP_FERNET_KEY` |
| Service | `app/services/whatsapp/embedded_signup.py` (`start_session`, `_consume_state`, `complete_with_state`, `validate_connection`, `disconnect`, `audit_tenant_test_message`) |
| Routes | `app/public/routes.py` → `GET /portal/whatsapp/embedded/config`, `POST .../start`, `POST .../complete`; portal actions `refresh_status` / `disconnect` / `send_test` |
| Frontend | `app/templates/public/customer_portal_dashboard.html` (WhatsApp pane) + `app/static/js/whatsapp_embedded.js` |
| Bridge status (thin client) | `app/api/routes.py` → `/api/integration/hoberadius/whatsapp/status` returns `onboarding_state` + `embedded_available` |
| Provider / Webhook (reused) | `app/services/whatsapp/providers.py`, `.../webhook.py` (`/api/whatsapp/webhook`) |

## Flow (state-bound, idempotent)

1. The pane loads `whatsapp_embedded.js`, which `GET`s `/embedded/config`
   (safe values only: `app_id`, `config_id`, `graph_version`, `enabled` — never
   the app secret) to decide availability.
2. On **Connect**, the client `POST`s `/embedded/start`. The server issues a
   one-time **state + nonce**, stores only their SHA-256 hashes as a *pending*
   `whatsapp_embedded_signup_attempts` row (with `expires_at`, `initiated_by`),
   expires any prior live attempt, and audits `embedded_signup_started`.
3. The browser runs `FB.login({config_id, response_type:'code', …, extras:{state}})`.
   The popup returns an authorization `code`; a `WA_EMBEDDED_SIGNUP` message
   (origin **strictly** `https://www.facebook.com` / `web.facebook.com`) carries
   the selected `waba_id` + `phone_number_id`.
4. The page `POST`s `{code, waba_id, phone_number_id, state, nonce}` (JSON, CSRF
   header) to `/embedded/complete`.
5. `complete_with_state()` (server): **validates the state/nonce** against the
   pending attempt for the *session customer* → `exchange_code` → read scopes →
   fetch phone + WABA metadata → subscribe the app to the WABA → persist via
   `upsert_account()` (**token encrypted**) → `connection_status='connected'`,
   `onboarding_method='embedded'` → finalize the attempt `completed` → audit
   `embedded_signup_succeeded`. A replayed callback returns the existing
   connection (idempotent) — no duplicate row, no second exchange.
6. The pane shows **✅ واتساب متصل** with name / number / masked WABA + Phone IDs
   / connected_at / last_sync_at and actions: **Send test message / Refresh
   status / Reconnect / Disconnect**.

### Connection states (UI)
`not_connected · connecting · connected · needs_attention (admin config
incomplete) · error · disconnected`. When the flag is on but creds are missing
the customer sees a friendly "إعداد الربط عبر Meta غير مكتمل من لوحة الإدارة" —
never a broken button.

### Lifecycle actions
- **Refresh status** → `validate_connection` re-probes Meta, updates
  `last_sync_at`/status/last_error, audits `whatsapp_connection_synced`.
- **Reconnect** → re-runs the embedded flow; credentials are replaced **only
  after** a new connection succeeds (a failed reconnect leaves the live
  connection intact); audits `whatsapp_connection_reconnected`.
- **Disconnect** → soft-disconnect (clears token, marks disconnected, keeps
  audit history), idempotent; audits `whatsapp_connection_disconnected`.
- **Send test message** → sends through the **connected tenant account** (never
  house creds), default template `hello_world`/first approved; audits
  `whatsapp_tenant_test_message_sent` / `_failed`.

### Audit taxonomy
`embedded_signup_started/succeeded/failed`, `whatsapp_connection_synced/
disconnected/reconnected`, `whatsapp_tenant_test_message_sent/failed`. Legacy
names `whatsapp_embedded_connected/disconnected` are still emitted during a
transition window. No metadata ever contains a token/secret.

## Prerequisites (you provide)

A Meta App configured as a **WhatsApp Tech Provider** with an **Embedded Signup
configuration**, in Live mode, with `whatsapp_business_management` +
`whatsapp_business_messaging`. Then set (env only — never commit):

```
WHATSAPP_FERNET_KEY=<generated fernet key>      # encrypts tokens at rest
WHATSAPP_EMBEDDED_SIGNUP_ENABLED=1
META_APP_ID=<your app id>
META_APP_SECRET=<your app secret>               # server-side only
META_CONFIG_ID=<your embedded-signup config id> # a.k.a. META_EMBEDDED_SIGNUP_CONFIG_ID
META_GRAPH_VERSION=v21.0
META_OAUTH_REDIRECT_URI=                          # optional; else derived
META_EMBEDDED_ATTEMPT_TTL_SECONDS=600
META_EMBEDDED_REQUIRE_STATE=1                     # recommended in production
```

Configure the Meta App's webhook callback URL to
`https://<panel-host>/api/whatsapp/webhook`; the panel verifies inbound POSTs
with the **app secret** (`X-Hub-Signature-256`). HTTPS is required for the
OAuth callback in production.

Until `META_APP_ID`/`META_APP_SECRET`/`META_CONFIG_ID` are set (or the flag is
`0`), the embedded CTA is **hidden** / shown as "setup incomplete" and the
manual "advanced" path remains — nothing breaks.

## Operations

- **Where customers go:** Customer portal → WhatsApp pane. From `radius-module`,
  the WhatsApp page shows the panel status (connected / not connected / needs
  setup) and an **"إدارة ربط واتساب"** deep-link to the panel pane.
- **Manual / house fallback:** the manual credential entry remains under
  «إعداد متقدم — إعداد يدوي للمسؤول فقط»; the admin Settings page manages the
  house Cloud API creds (encrypted, super-admin reveal, audited).
- **Schema:** `db.create_all()` creates `whatsapp_embedded_signup_attempts` on
  fresh and existing DBs; `ensure_schema_compatibility()` carries the additive
  column-evolution hook. No Alembic migration needed.
- **Key management:** `WHATSAPP_FERNET_KEY` must be stable. Rotating it makes all
  stored tokens unrecoverable (customers must reconnect).

## Backward compatibility & rollback

- Manual path preserved (`save_credentials` / `validate` actions unchanged).
- Schema changes are additive, nullable (existing rows = `manual`); the new
  attempts table is additive and only written behind the flag.
- **Rollback** = set `WHATSAPP_EMBEDDED_SIGNUP_ENABLED=0` (CTA disappears,
  manual + house paths remain). Added columns/table are harmless if left.

## Security

- Tokens encrypted at rest (Fernet, `WHATSAPP_FERNET_KEY`); never logged, never
  returned to the browser, never in exception text or audit metadata.
- `app_secret` is server-side only — never in `/embedded/config` or any
  customer response. The only app-secret UI is the admin-only, super-admin-gated
  house-settings page (write-only input + audited reveal).
- Embedded Signup is **state/nonce-bound**: the completion callback must echo a
  valid, unexpired, single-use, tenant-scoped state — replays/forgeries fail
  closed and are audited.
- Every action is scoped to the **session customer** (a body `customer_id` is
  ignored); `whatsapp_gateway` entitlement required; CSRF enforced.
- Webhook POSTs verified against the app secret (constant-time). Strict webhook
  signature mode and token auto-refresh are tracked for a later phase.
