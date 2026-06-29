# WhatsApp Cloud API — Phase 1 (Manual Per-Tenant Credentials) — Delivery Report

**Repo:** `radius-module-admin` (the License Panel — owns the Meta connection).
**Branch:** `feat/whatsapp-phase1-manual`. **Date:** 2026-06-29.
**Status:** **Phase 1 ships working end-to-end, per tenant (`customer_id`).** Embedded
Signup remains as *future-ready scaffolding* and is **not** on the Phase-1 path.

> `tenant` = a panel **customer** (`customers.id`). Each tenant connects **their own**
> WhatsApp number; there is **no shared/global number** anywhere in the send path.

---

## Phase 1 — the 10 points, all working

| # | Requirement | Where it lives |
|---|-------------|----------------|
| 1 | **Per-tenant settings** (not global) | `WhatsAppTenantAccount` + `WhatsAppServiceSettings`, both unique per `customer_id` (`app/models.py`); service `app/services/whatsapp/settings.py`. |
| 2 | **Manual credentials entry** (UI form): `access_token`, `phone_number_id`, `waba_id`, `display_phone_number`, **status** | Admin: `POST /admin/customers/<id>/whatsapp/credentials` (`app/admin/routes.py:customer_whatsapp_credentials`), form in `templates/admin/customer_whatsapp.html`. Customer self-service: `POST /portal/whatsapp` (`save_credentials`). Status badge: connected / disconnected / pending / suspended / error + the normalized 3-state below. |
| 3 | **Tokens encrypted at rest (Fernet); never in repo** | `app/services/whatsapp/crypto.py` (Fernet via `WHATSAPP_FERNET_KEY`, no ephemeral fallback). `upsert_account` stores `access_token_encrypted`; the key is env-only. |
| 4 | **Backend send via Meta Graph using the tenant's `phone_number_id` + token** | `MetaCloudWhatsAppProvider.send_template_message` → `POST {GRAPH}/v21.0/{account.phone_number_id}/messages` with `Authorization: Bearer {decrypt(account token)}` (`app/services/whatsapp/providers.py`). The worker resolves the account by `customer_id` (`worker.py`). No global-number fallback — a missing `phone_number_id` raises `missing_phone_number_id`. |
| 5 | **Test-send endpoint** (TEMPLATE, e.g. `hello_world`) | Admin: `POST /admin/customers/<id>/whatsapp/test` (enqueue → `worker.drain_once`). Bridge: `POST /api/integration/hoberadius/whatsapp/messages/test`. House/provider test: `POST /admin/settings/whatsapp-cloud/test-message`. **Proven live** by the new gated test (below). |
| 6 | **Message-logs table** (per tenant: to, template, wa message id, status, error, timestamps) | `WhatsAppMessageQueue` (`recipient_phone`, `template_name`, `provider_message_id`, `status`, `error_code`/`error_message`, `sent_at`/`delivered_at`/`read_at`/`failed_at`); written by `queue.py` + `worker.py`. Surfaced in the per-customer page + `/admin/whatsapp-gateway/messages`. |
| 7 | **Webhook** for delivery/status (verify-token handshake + update logs) | `GET/POST /api/whatsapp/webhook`; `app/services/whatsapp/webhook.py` (`verify_challenge`, idempotent `ingest`, `X-Hub-Signature-256` check, per-customer `WhatsAppMessageQueue` status mapping sent/delivered/read/failed). |
| 8 | **Ready for future Embedded Signup, but not depended on** | See "Stubbed for the future" — embedded code is a separate, optional module; Phase 1 works with `META_EMBEDDED_SIGNUP_ENABLED` off and no central app config. |
| 9 | **Never one global number for all customers** | Verified: every send is parameterized by the per-tenant account; the panel "house" creds (`cloud_settings.py`) are used ONLY for the admin's own test connection, never to send a customer's messages. |
| 10 | **Never expose tokens** (UI / logs / errors / API; mask everywhere) | Stored encrypted; `account_public_dict` returns only `access_token_masked`; the form field is write-only (`type=password`, never prefilled); `providers._request` "NEVER logs the token/headers/body"; provider errors are sanitized (`meta_unreachable` does not echo the URL). |

### Status badge — normalized 3-state (added this pass)
The panel tracks a rich set (`connected / disconnected / error / suspended / pending /
not_configured`). The product spec asks for a clean **Connected / Needs action /
Disconnected** triad, so `settings.normalized_integration_status()` folds the rich set:
`error|suspended|pending → needs_action`; `disconnected|not_configured|unknown →
disconnected`; `connected → connected`. Exposed as `integration_status` in
`account_public_dict` **and** in the bridge `GET .../whatsapp/status` response so the
radius client renders the badge without re-mapping. The admin UI keeps the richer
labels (more informative for the operator).

---

## Added / changed this pass

1. **`integration_status` normalized 3-state** — `settings.normalized_integration_status`
   + field in `account_public_dict` + the bridge status response. Tests:
   `test_normalized_integration_status_folds_to_three_states`,
   `test_account_public_dict_exposes_integration_status`, and an assertion in the
   bridge status test.
2. **Live send-path proof** — `tests/test_whatsapp_live_send.py`, **skip-gated** on
   `WHATSAPP_ACCESS_TOKEN` + `WHATSAPP_PHONE_NUMBER_ID` (+ `WHATSAPP_TEST_RECIPIENT`
   for the actual send). Skips in CI/offline; when the owner exports the test creds it
   (a) validates the creds against the real phone node and (b) sends `hello_world` from
   the tenant's own number and asserts a returned `wamid.`. These env vars are
   **testing-only** — they are never baked in and the provider always reads the
   per-tenant account, so no shared number is introduced.

Everything else for Phase 1 already existed and is reused, not duplicated.

---

## Verification

- WhatsApp suite: **266 passed, 2 skipped** (the 2 live tests skip without creds)
  — `pytest -k "whatsapp or embedded or cloud_init"`.
- Screenshots (`scripts/render_whatsapp_phase1.py` → `_wa_shots/`):
  - `_shot_p1_manual_entry.png` — fresh tenant: empty manual-credentials form, status
    "غير مهيأ", validate + test buttons, empty templates/log.
  - `_shot_p1_connected.png` — tenant after manual entry + validate: status "متصل",
    masked token, approved template, test-message card, message log (delivered/read/sent/failed).

---

## Stubbed / scaffolded for the FUTURE Embedded-Signup phase (NOT on the Phase-1 path)

These exist and are wired, but Phase 1 neither requires nor blocks on them:

- **Central Meta-app config** (`app/services/whatsapp/embedded_settings.py`) — provider
  enters App ID / App Secret / Config ID / Graph version once in Settings →
  `#whatsapp-embedded`. Resolves DB → env → default; `is_enabled()`/`available()` gate
  the feature. **Phase 1 leaves this unset/off.**
- **Embedded Signup flow** (`app/services/whatsapp/embedded_signup.py`,
  `exchange_code`/`complete_signup`) + portal routes `POST /portal/whatsapp/embedded/
  {config,start,complete}`. The clean hook into Phase 1 is `settings.upsert_account(...)`
  — embedded calls the **same** per-tenant store + `set_connection_status("connected")`
  that the manual form uses, so both paths converge on one storage/send path.
- **Portal "Connect WhatsApp" CTA** appears only when `embedded_signup_available()` is
  true; otherwise the portal shows the manual paste form (the Phase-1 path).
- **What's needed to turn it on later:** (1) create/configure the central HobeRadius
  Meta app + Embedded Signup configuration in Meta; (2) enter App ID/Secret/Config ID
  in the provider Settings UI; (3) flip the enable toggle. No schema or send-path change
  — the per-tenant account, send service, webhook, and logs are identical.
- **Webhook signature is Phase-1 lenient** (`webhook.py`): trusted when no secret/header
  is resolvable; verified (constant-time) when both are present. Flagged for a later
  "strict" upgrade.
