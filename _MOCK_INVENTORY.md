# MOCK / DISPLAY-ONLY / TERMINAL-ONLY INVENTORY — radius-module-admin

**Audit date:** 2026-06-10
**Repo state:** `main` at 2d92327 (fleet work merged through Phase 6 task C)
**Scope:** every admin page/section/feature; bridge endpoints; section visibility/RBAC; activation tokens; fleet phased work flagged separately.
**Method:** read-only — source files were inspected, no file was modified.

Owner rule audited against: **zero demo/mock/display-only/fake features** + **everything activatable/configurable from the ADMIN UI** (never terminal/env/CLI).

Severity legend: **🔴 HIGH** (owner-rule violation, user-visible) · **🟠 MED** (real impact, partial) · **🟡 LOW** (cosmetic / contained).

Columns: `[feature]` | `[file:area]` | `[why not real / terminal-dependent]` | `[what "real & UI-driven" requires]` | `[DOABLE-NOW vs NEEDS-OWNER-INPUT]`.

---

## A. MOCK / FAKE / hardcoded sample data rendered as real

| feature | file:area | why not real | what real & UI-driven requires | DOABLE-NOW vs NEEDS-OWNER-INPUT |
|---|---|---|---|---|
| 🔴 **License → Services catalog (per-license)** rendered with **fake usage counters** (e.g. `230/500 مشتركين`, `45/100 جلسات`, `320/1000 بطاقات`, `12/20 NAS`, `5/30 تقارير الشهر`, etc.) | `app/admin/services_data.py:4-221` (`SERVICES_MOCK`) consumed by `app/admin/routes.py:1887-1919` (`_effective_services_for_license`) and rendered by `app/templates/admin/licenses/services_new.html:720-781` | `SERVICES_MOCK` is a Python literal with hand-written `limits.current`/`limits.max` numbers. Comment line 1-2 admits "بيانات وهمية … ستُستبدل لاحقاً بـ DB query". `LicenseServiceOverride` only patches `max` — `current` stays fake. So the owner is shown numbers that look like real usage but never move. | Replace with a real **service catalog table** (already exists: `ServiceCatalogItem`, `CustomerServiceEntitlement`, `CustomerServiceRequest`) + per-customer counters sourced from the radius bridge (the panel doesn't observe usage today; the customer's radius is the SoR for counts). Need: (1) a new bridge endpoint where the customer radius reports current usage per service-key per cycle; (2) panel cache table; (3) replace `SERVICES_MOCK` reads with the cache. UI form for catalog editing already exists in part (`CustomerServiceEntitlement` admin pages). | **NEEDS-OWNER-INPUT** for the contract shape (which counts to expose per service-key, cycle reset semantics). Implementation is then DOABLE-NOW. |
| 🟡 Service catalog icons + descriptions hardcoded inside `SERVICES_MOCK` | `app/admin/services_data.py` (e.g. `"icon": "👥"`, `"description": "إدارة حسابات المشتركين…"`) | Catalog metadata is mostly stable but the owner has no UI to edit it. `ServiceCatalogItem` model has `name_ar`/`description`/etc. but the license-services page reads from `SERVICES_MOCK` not from the DB. | Read from `ServiceCatalogItem` (already used elsewhere); add a small "Service catalog editor" page (icon + description + default limits + category). | **DOABLE-NOW** |

> Verified clean: dashboard KPIs (`app/admin/routes.py:402-419`), customer detail (counts come from `radius_admins_for_customer` + `customer.users` queries), licenses list/dashboard, audit logs — **all live DB queries, no fixed numbers**.

---

## B. DISPLAY-ONLY UI — forms/buttons with no real backing

| feature | file:area | why not real | what real & UI-driven requires | DOABLE-NOW vs NEEDS-OWNER-INPUT |
|---|---|---|---|---|
| 🔴 **`/settings/admins`** — the entire admin-users management page is **non-functional**. Add admin, edit admin, enable, disable, delete buttons all POST to `action="#"`. | `app/templates/admin/settings/admins_new.html:522-544` (enable/disable forms), `:587` (create form), `:672` (delete form). Handlers: NONE. Only GET `/settings/admins` exists (`app/admin/routes.py:2324-2343`). Grep for `admins` POST in `app/admin/routes.py` returns zero. | Forms render real `<form>` markup with CSRF token but `action` is `#`, so the browser navigates to `#` (no-op). The page LOOKS functional. Users can submit the modal and see no feedback. | Add four real POST handlers under `/settings/admins/*`: create (with bcrypt password generation + email), update (role/active/email/full_name), enable/disable (set `Admin.active`), delete (deny self-delete, audit log). All four already have ready forms in the template — just wire them up. Handler decorators: `@super_admin_required` (admin management must not be open to operators). | **DOABLE-NOW** — schema (`Admin` model) is already complete and used at login. |
| 🔴 **`/settings/whatsapp`** — standalone WhatsApp settings page is **fully cosmetic**. All five forms (connection, test, templates × 3) POST to `action="#"`. | `app/templates/admin/settings/whatsapp_new.html:353,395,430,558` (action="#"). The page is rendered by `settings_whatsapp()` at `app/admin/routes.py:2291-2309`. | The REAL WhatsApp Cloud settings UI lives in `general_new.html` (with handlers `whatsapp_cloud_save/test/test-message/reveal/templates` at `app/admin/routes.py:2383-2478`). This whatsapp_new.html page is a duplicate that the owner can navigate to via `/settings/whatsapp` and submit forms that do nothing. | Either delete the `/settings/whatsapp` route + template (redirect to `/settings#whatsapp-cloud` which already has the real forms) OR wire the new forms to call the same `cloud_settings.validate_and_save()` service. | **DOABLE-NOW** — service layer is already implemented and used by the working page. |
| 🔴 **`/settings`** general page — site_info (`site_name/tagline/address/logo upload`), Google OAuth client editor, multiple sections POST to `action="#"`. | `app/templates/admin/settings/general_new.html:407` (site info form), `:530`, `:649` (other sections). Only the bottom-of-page "settings_update" form posts to `/settings` and accepts a fixed key list (`product_name, license_api_base_url, default_grace_days, default_currency, support_email, support_phone, check_interval_recommendation, environment_label, google_oauth_*`). Logo upload, site_logo file field — not handled anywhere. | The Settings page tabs labeled "site info" + "logo upload" exist visually but no upload handler / no setting persistence for `site_logo`, `site_name`, `site_tagline`, `site_address`. | Add `POST /settings/site-info` that persists the keys to the `Setting` table (template already uses `{{ settings.site_name }}` etc.), plus file upload route saving the logo to `app/static/uploads/` and recording the path in `Setting`. | **DOABLE-NOW** |
| 🟡 Customer portal "manual WhatsApp setup" link `<a href="#">` (5 places) | `app/templates/public/customer_portal_dashboard.html:481,483,489,499,511` | Anchor with `href="#"` and `data-wa-toggle-advanced` — this IS the toggle for an advanced section in the same page (JS-handled). Not a dead link. **VERIFIED OK on closer reading.** | — | — |
| 🟡 Sidebar "fleet" links live, sub-link "DNS front-door" wired (P6 task C). Verified working. | `app/templates/admin/base_new.html:228-253` | — | — | — |

---

## C. STUB endpoints / services returning canned data (NON-FLEET)

| feature | file:area | why not real | what real & UI-driven requires | DOABLE-NOW vs NEEDS-OWNER-INPUT |
|---|---|---|---|---|
| 🟡 **WhatsApp generic providers** raise `NotImplementedError` | `app/services/whatsapp/providers.py:95,107,111,115,119,123` (`send_text_message`, etc.) | Intentional abstract base — Cloud + Embedded providers override these. The base class is the contract, never instantiated. **VERIFIED — not a runtime stub.** | — | — |
| 🟡 SMS adapter "single TODO" placeholder | `app/services/messaging/adapters/sms.py:39` | One `# TODO(messaging): adjust _build_request to match the concrete SMS gateway`. The adapter has a default `_build_request` that works for typical REST SMS gateways — it's a customization seam, not a stub. The route handler is real. | If the chosen SMS gateway requires non-standard request shape, the owner currently has no UI to change the request format — but can switch `base_url`/`api_key` via the messaging settings page. | **NEEDS-OWNER-INPUT** (which SMS gateway provider is being targeted?) |
| 🟡 Telegram adapter parse_mode TODO | `app/services/messaging/adapters/telegram.py:32` | A comment about default parse_mode choice. Adapter itself works. | — | — |

---

## D. Terminal/env/CLI-only configuration — VIOLATIONS OF ALL-FROM-UI RULE

### D.1 Secret bootstrap (must stay env) — acknowledged unavoidable
These ARE correctly env-only because they wrap everything else; rotating them would invalidate already-encrypted data.

| key | file | UI alternative | Notes |
|---|---|---|---|
| `WHATSAPP_FERNET_KEY` | `app/config.py:82`, used by `app/services/whatsapp/crypto.py` | none — wraps every WhatsApp secret + the vault key itself | **Correct** — bootstrap-only. Settings UI flags this clearly when missing. |
| `CUSTOMER_VAULT_ENCRYPTION_KEY` | `app/config.py:94`, used by `app/services/customer_vault_crypto.py` | UI form **does** exist at `/settings` (vault tab) — can be set/cleared via `POST /settings/vault/key` (`app/admin/routes.py:2640`). Falls back to env if no DB value. | **OK** — env is bootstrap fallback only; UI persistence implemented. |
| `LICENSE_CHECK_HMAC_SECRET` | `app/config.py:68`, used by license signing + bridge integration | none | **Correct** — bootstrap-only (rotating breaks all customer radius instances). Add UI READ to confirm "configured ✓" without revealing. |
| `RADIUS_PROXY_SHARED_SECRET` | `app/config.py:196`, used by `app/api/proxy_api.py` HMAC | none | **Correct** — must match proxy side. Add UI READ to confirm "configured ✓". |
| `FLASK_SECRET` | `app/config.py:47` | none | **Correct** — session signing. |

### D.2 Operational defaults — env-only but SHOULD be UI-editable Settings

| 🟠 key | file:line | why this is a violation | what real & UI-driven requires |
|---|---|---|---|
| `DEFAULT_GRACE_DAYS` (7) | `app/config.py:52`, read by `app/services/license_service.default_grace_days()` | Customer-visible setting (license grace after expiry). No UI form to change. Seed inserts a `Setting` row (`default_grace_days`) but the code reads `current_app.config["DEFAULT_GRACE_DAYS"]` instead of the Setting. | Read from `Setting` first, fall back to env. Add a numeric field on `/settings` general tab. **DOABLE-NOW.** |
| `DEFAULT_CURRENCY` | `app/config.py:53` | Has UI write at `settings_update` (`app/admin/routes.py:2353`) **and** it's read from `Setting` in payment code. **OK — verified.** | — |
| `SUPPORT_EMAIL` / `SUPPORT_PHONE` | `app/config.py:54-55` | Same as default_currency — UI form persists them. **OK.** | — |
| `CHR_DEFAULT_MAX_TUNNELS` (5) | `app/config.py:152` | No UI form. Used as default cap when provisioning per-customer VPN tunnels. Hidden tunable. | UI form on the customer-VPN-tunnels admin page (per-customer override already exists; only the global default is env-only). **DOABLE-NOW.** |
| `CHR_DEFAULT_PPP_PROFILE` | `app/config.py:154` | No UI form. | UI field in CHR settings card. **DOABLE-NOW.** |
| `CHR_PPP_LOCAL_ADDRESS` (10.98.0.1), `CHR_PPP_ADDRESS_POOL`, `CHR_PPP_POOL_RANGES`, `CHR_PPP_USE_ENCRYPTION` | `app/config.py:159-165` | All env-only IP-pool config for the central CHR PPP server. CHR settings UI covers `host/port/username/password/public_host/public_ip/IPsec` but NOT these PPP-pool keys. | Extend CHR settings form to include the PPP-pool block + persistence. **DOABLE-NOW.** |
| `CHR_IPSEC_*` (peer / mode_config / profile / eap_methods / address_pool / dns / certificate) | `app/config.py:181-190` | The IPsec block is partially in the CHR settings UI (`ipsec_certificate`, `ipsec_address_pool` are persisted) but `CHR_IPSEC_PEER/MODE_CONFIG/PROFILE/EAP_METHODS/DNS` are NOT. | Extend the form with the missing fields. **DOABLE-NOW.** |
| `RADIUS_PROXY_TOKEN_TTL` (60s) | `app/config.py:198` | Anti-replay window for proxy HMAC tokens. Operationally tunable; env-only. | UI numeric field in CHR/proxy settings. **DOABLE-NOW.** |
| `LICENSE_CHECK_*_RATE_LIMIT_*` | `app/config.py:62-67` | All rate-limit knobs env-only. | UI form in a "rate limits" settings section. **DOABLE-NOW.** |
| `META_APP_ID`, `META_APP_SECRET`, `META_CONFIG_ID`, `META_OAUTH_REDIRECT_URI` | `app/config.py:103-108` | Used by Embedded Signup, but admin actually persists them via `/settings/whatsapp-embedded` POST (`app/admin/routes.py:2486`) into `Setting` rows. Env is bootstrap fallback. **OK.** | — |
| `WHATSAPP_ACCESS_TOKEN`, `WHATSAPP_PHONE_NUMBER_ID`, `WHATSAPP_BUSINESS_ACCOUNT_ID` | `app/config.py:206-208` | Persisted via `/settings/whatsapp-cloud` (`cloud_settings.validate_and_save`). Env is bootstrap fallback. **OK.** | — |
| `WHATSAPP_DEFAULT_TIMEZONE`, `WHATSAPP_DEFAULT_COUNTRY` | `app/config.py:88-89` | No UI form for these display/locale defaults. | UI field in WhatsApp settings card. **DOABLE-NOW.** |

### D.3 CLI commands — operational scripts that should not require terminal

The following CLI commands exist (`app/__init__.py`). For background jobs they are typically scheduled (systemd timer / cron), so terminal-free; but if no scheduler is configured, the owner must run them by hand — **that violates the rule**.

| command | purpose | currently scheduled? | what real & UI-driven requires |
|---|---|---|---|
| 🟠 `app whatsapp-drain` | drain queued WhatsApp messages | requires systemd timer | UI "scheduled tasks" section to list/start/stop the timer + last-run timestamp. **DOABLE-NOW** — show + audit. |
| 🟠 `app vpn-quota-sync` | sync VPN quota from CHR | requires systemd timer | same — UI to show schedule, run-now button (already a per-customer "sync now" exists on the customer-VPN-tunnels page). |
| 🟠 `app collect-chr-metrics` | poll CHR metrics | requires systemd timer | UI section: status, run-now, last run + audit. |
| 🟠 `app enforce-allocations` | enforce per-customer service allocations | requires systemd timer | UI section in infra → service allocations: status, run-now, audit. |
| 🟢 `app init-db`, `app bootstrap-admin` | one-time setup at deployment | OK — terminal is acceptable for the initial bring-up; bootstrap mode UI already exists at `/setup`. | — |

### D.4 Test-server / dev-only knobs in production config

| 🟡 issue | file:line | notes |
|---|---|---|
| `META_EMBEDDED_REQUIRE_STATE = False` by default | `app/config.py:115` | OAuth state parameter optional by default — should be `True` in strict env. UI does not surface this. (Cosmetic; embedded signup not yet in use in current deployment.) |
| `CHR_TLS_VERIFY = False` default | `app/config.py:143` | Self-signed CHR cert acceptable in lab, but no UI banner warns the operator when running with TLS verification off. UI field exists (`verify_tls` in CHR settings). |

---

## E. PARTIALLY-BUILT features (TODO / FIXME / NotImplementedError / pass-only)

| 🟠 feature | file:line | status |
|---|---|---|
| **WhatsApp send to "owner" channel — TODO in queue → send glue** | `app/services/messaging/adapters/whatsapp.py:59` (`# TODO(messaging): this single call site is where outbound WhatsApp …`) | TODO in adapter glue. Cloud-settings UI works for tokens, but live send may have a single edge unfinished. **NEEDS VERIFICATION** by running `messaging.test_send("whatsapp", recipient)` end-to-end. |
| Fleet `_notify_hook` Phase-9 stub | `fleet/health/monitor.py:375-385` | Explicitly documented Phase-9 TODO. Events are recorded; no notification dispatch. See section I. |
| Customer-portal: `pass` in landing CMS placeholder filter | `app/services/landing_cms.py:319` (`# Contact methods — hidden placeholders (admin enables + fills; we never invent data)`) | This is GOOD — explicit refusal to fabricate. **VERIFIED OK.** |
| Embedded signup mock network seam | `app/services/whatsapp/embedded_signup.py:278-288` | Single mockable point — used by tests, real path goes to Meta Graph API. **VERIFIED OK.** |

---

## F. SECTION HIDE / RBAC FINDINGS

### F.1 Section hide — sidebar-only, NOT server-enforced

| 🔴 finding | evidence |
|---|---|
| `get_hidden_sections()` is called from EXACTLY TWO places: the global template context processor (`app/__init__.py:761`) which feeds `{% if 'X' not in hidden_sections %}` checks in `base_new.html`, AND the settings UI itself (`app/admin/routes.py:2320`). | grep for `get_hidden_sections|hidden_sections` outside `templates/admin/base_new.html` returns no route guard. |
| **No route uses `hidden_sections` to deny access.** A logged-in admin who hits e.g. `/admin/customers/` directly while "customers" is hidden still gets the page (HTTP 200). | Direct URL → controller code → no visibility check. |
| The settings page calls itself a "show/hide sidebar" page, not "disable section", so technically by-design — **but the owner rule** "hiding a section should hide AND block" is not met if interpreted strictly. | `app/admin/section_visibility.py:1-3` docstring: "helper لإظهار/إخفاء أقسام السايدبار" (sidebar only). |

**What "real" requires:** add a `before_request` hook on the admin blueprint that maps the current `endpoint` (or URL prefix) to a section key, looks it up in `get_hidden_sections()`, and `abort(404)` if hidden. Keep a per-endpoint override map (e.g. `_PUBLIC_ENDPOINTS = {"admin.settings_page", "auth.login_post"}` etc. always pass through). **DOABLE-NOW** — small wrapper, no schema change.

### F.2 RBAC — sensitive routes that are `@login_required` instead of `@super_admin_required`

| 🟠 route | file:line | risk | recommendation |
|---|---|---|---|
| **Payment approve** | `app/admin/routes.py:2787-2803` | Any operator can approve a manual license payment ⇒ activates billing. | `@super_admin_required`. |
| **Payment reject** | `app/admin/routes.py:2806-` | Less severe but still financial. | `@super_admin_required` OR keep `@login_required` but require super-admin to overturn an approval. |
| **Customer-vault record CRUD (non-secret)** | `app/admin/vault_routes.py:64-97` | Any admin can edit a customer's business records (bank details visible as metadata). | Intentional per file comment ("records → any active admin; secrets → super only"). **Owner call needed.** |
| **Set license status** (`/licenses/<id>/suspend|activate|revoke`) | `app/admin/routes.py:2134-2156` | Any operator can revoke a license. | `@super_admin_required` for revoke, leave suspend/activate as `@login_required`. |
| **Issue activation token** | `app/admin/routes.py:3459-` | Already `@super_admin_required`. **OK.** | — |
| **All `*/reveal` (whatsapp + CHR password + embedded secret)** | already `@super_admin_required`. **OK.** | — | — |
| **Customer disable (status=blocked)** | `app/admin/routes.py:1522-1525` via `customer_edit` | Any operator. | Suggest `@super_admin_required` for status flips. |

---

## G. SECTION DISABLE / SUSPEND FINDINGS

### G.1 Customer status — partial end-to-end enforcement

A customer can be put into `blocked/inactive/pending` via the customer-edit form (`app/admin/routes.py:1522-1525`). What ACTUALLY stops:

| target | enforces customer.status? | evidence |
|---|---|---|
| Customer-portal login | ✅ yes | `app/public/routes.py:113,201` — both routes refuse if `customer.status != "active"`. |
| 🔴 **Bridge `/api/integration/hoberadius/runtime-contract`** | **NO** | `app/api/routes.py:110-131` calls `build_runtime_contract_for_license()` which only checks `license_active`/`license.status`. A blocked customer with an active license keeps receiving services. |
| 🔴 **Bridge `/api/integration/hoberadius/identity-sync`** | **NO** | `app/api/routes.py:90-107` same pattern. Blocked customer's users keep getting synced to the customer radius. |
| 🔴 **Bridge `/api/integration/hoberadius/capacity-contract`** | **NO** | Same pattern. |
| Other 17 bridge endpoints (whatsapp, vpn tunnels, service-activations poll, etc.) | mixed — most check license.status, none check `customer.status` | `app/api/routes.py:*` — searched. |

**What "real" requires:** central guard — in `_checked_license_from_integration_body()` (which every endpoint calls) add a `customer.status` check; if blocked/inactive return `{"ok": False, "status": "customer_blocked"}` with HTTP 403. **DOABLE-NOW** — single chokepoint, all bridge endpoints inherit it.

### G.2 License status (suspend/revoke) — fully enforced

✅ `set_license_status()` + `license_allows_vpn_services()` in `app/services/vpn_entitlements.py:139-144` correctly excludes suspended/revoked/expired-without-grace. Bridge endpoints respect this. **OK.**

### G.3 Service entitlement enable/disable — enforced

✅ `CustomerServiceEntitlement.status` and `.enabled` flow into the runtime contract and per-service handlers. **OK.**

---

## H. PANEL ↔ RADIUS INTEGRATION FINDINGS

### H.1 Bridge endpoints — all real, all signed, all HTTPS-required

Verified all 20 endpoints under `/api/integration/hoberadius/*` in `app/api/routes.py`:

| endpoint | real impl? | HMAC signature? | HTTPS required? | notes |
|---|---|---|---|---|
| `identity-sync` | ✅ | ✅ `_verify_integration_signature()` | ✅ `_integration_request_is_secure()` | real DB-backed user list. |
| `runtime-contract` | ✅ | ✅ | ✅ | misses customer-status check (see G.1). |
| `capacity-contract` | ✅ | ✅ | ✅ | same. |
| `service-requests` | ✅ | ✅ | ✅ | persists `CustomerServiceRequest`. |
| `portal-sso` | ✅ | ✅ | ✅ | real one-time SSO token mint. |
| `google-drive/status` | ✅ | ✅ | ✅ | reads `google_drive.status()`. |
| `customer-users/password-change` | ✅ | ✅ | ✅ | updates `CustomerUser.password_hash` (`set_password`). |
| `admins/report` | ✅ | ✅ | ✅ | upserts `CustomerRadiusAdmin` snapshot. |
| `backups/upload` | ✅ | secret header OR signature | ✅ | reverse-channel upload via `customer_backups.record_backup_upload`. |
| `whatsapp/status` | ✅ | ✅ | ✅ | returns `cloud_settings.get_state()` for the customer's tenant. |
| `whatsapp/messages/enqueue` | ✅ | ✅ | ✅ | real queue write. |
| `whatsapp/messages/test` | ✅ | ✅ | ✅ | real send through `cloud_settings`. |
| `whatsapp/cloud-test` | ✅ | ✅ | ✅ | real Graph API call. |
| `whatsapp/subscriber-preferences/sync` | ✅ | ✅ | ✅ | real. |
| `whatsapp/messages/status` | ✅ | ✅ | ✅ | real. |
| `vpn/tunnels/request` | ✅ | ✅ | ✅ | creates `CustomerVpnTunnel` request rows. |
| `vpn/tunnels` (list) | ✅ | ✅ | ✅ | real query. |
| `vpn/tunnels/ack` | ✅ | ✅ | ✅ | real state transition. |
| `service-activations/poll` | ✅ | ✅ | ✅ | real. |
| `usage-snapshot/push` | ✅ | ✅ | ✅ | real `ServiceUsageSnapshot` upsert. |
| `instance-ops/heartbeat` | ✅ | ✅ | ✅ | real `InstanceActivationToken` consume + heartbeat. |
| `instance/activate` | ✅ | activation code IS the credential (no HMAC pre-shared) | ✅ | well-designed single-use + audit logging. Real `InstanceActivationToken` table. |

**Verdict:** ✅ no stubs in the bridge.

### H.2 Activation tokens

✅ **Real and complete.** UI generation: `POST /admin/customers/<id>/activation-token/generate` (`app/admin/routes.py:3459`, `@super_admin_required`). Consumption: `POST /api/integration/hoberadius/instance/activate` (`app/api/routes.py:1059-1164`). Single-use via `used_at`. Expiry honored. SHA-256 hash stored, plaintext never logged.

### H.3 Half-wired pieces

| 🟠 issue | file:line | notes |
|---|---|---|
| `runtime-contract` does not project `customer.status` blocked → no-services | `app/api/routes.py:110-131` | See G.1. |
| Bridge `/admins/report` populates `CustomerRadiusAdmin` snapshot — the radius-side **producer is documented but not implemented in the customer radius-module** (per memory) | `app/services/customer_control.py:1091-1130` (panel side is real) | The panel side is real; the consumer (the customer's radius) needs to POST. Not a panel-side gap, but worth flagging. |
| No UI to **rotate** `LICENSE_CHECK_HMAC_SECRET` once issued | env-only, `app/config.py:68` | By design (would break every customer radius). Add UI READ-only "configured ✓" indicator. |

---

## I. FLEET (in-progress phased build) — STUBS SEPARATED

**Current state (post-Phase-6-C merge):** the real implementations LAND across phases; the adapters that the UI uses are designed with `BACKEND ∈ {"real","stub","fake"}` autodetect:

| component | adapter file | backend value at HEAD | evidence |
|---|---|---|---|
| Brain ranking (`best_node`, `top_n`, `rank`) | `fleet/brain/brain_adapter.py` | `BRAIN_BACKEND = "real"` | `fleet/brain/__init__.py:16-17` re-exports `best_node`, `top_n`, `rank` from real `scoring.py` + `placement.py` → `_discover_brain()` finds them. |
| Cloudflare DNS driver | `fleet/dns/driver_adapter.py` | `DRIVER_BACKEND = "real"` | `fleet/dns/driver.py` re-exports `apply_desired_state` from `fleet/dns/cloudflare.py` (860 LOC of real impl). |
| DNS reconciler (`preview`, `reconcile_now`) | `fleet/dns/reconciler.py` | real, settings-aware | `fleet/dns/reconciler.py` reads `settings_store` (mode + token), builds `ReconcileConfig`, delegates to `fleet/dns/reconcile.py:368,385` (567 LOC real impl). |
| Health monitor (`check_now`, `state_of`) | `fleet/health/monitor.py` | real, but `_notify_hook` is **explicitly Phase-9 TODO** (line 375) | sensing/state-machine works; outbound alerts deferred. |
| Health telemetry ingest | `fleet/health/routes_telemetry.py` | real | DB-backed insert + 2-table joins. |
| Placement decision endpoint | `fleet/brain/routes_placement_decision.py` | real via brain_adapter | — |
| Front-door settings store (Cloudflare token + mode) | `fleet/dns/settings_store.py` | real | encrypted via `WHATSAPP_FERNET_KEY` Fernet, masked from ciphertext, single-decrypt only in driver. |
| Onboarding service | `fleet/registry/onboarding_service.py` + `bootstrap_push.py` + `wg_keys.py` + `script_render.py` + `secrets_vault.py` | real | full state machine + WireGuard keygen + RouterOS script render + per-CHR secret vault. |
| Fleet UI dashboards | `fleet/ui/routes.py`, `dashboard_data.py`, `brain_view.py`, `dns_reconciler_view.py`, `frontdoor.html`, `onboarding_wizard.html` | real for routes + data assembly. **UI banner stale:** `brain_view.RankedNode.source = "fallback"` is still set in some local-rank paths even though the real brain is wired; `dns_reconciler_view._real_reconciler` import succeeds, but the fallback path can still be hit if the real call raises. | minor cosmetic — owner banner reads "تقدير مؤقت" when it should read "المنسّق الفعلي" in normal runs. |

### I.1 Fleet stubs that REMAIN at HEAD

| 🟠 stub | file:line | what remains |
|---|---|---|
| Phase-9 notifier (`fleet.notify`) | `fleet/health/monitor.py:375-385`, `fleet/notify/__init__.py` (empty package) | Events are recorded in the `Event` table; no SMS/WhatsApp/Telegram dispatch on transitions. Phase-9 owns this. |
| DNS driver "fake" path | `fleet/dns/driver_adapter.py:113-162` | Dead code at runtime now that `fleet.dns.driver` re-exports the real Cloudflare driver — kept for test fixtures. |
| Brain "stub" path | `fleet/brain/brain_adapter.py:130-214` | Same as above — kept for tests + safety fallback if `fleet.brain.placement` ever fails to import. |
| UI fallback bands (`brain_view`, `dns_reconciler_view`) | `fleet/ui/brain_view.py:115,135,286,292`; `fleet/ui/dns_reconciler_view.py:108,118,160` | The dashboards display "تقدير مؤقت في اللوحة" / source="fallback" when the real call short-circuits. Real path is preferred but the fallback runs on import failure or empty result. Cosmetic — should now consistently show real. |

### I.2 Fleet — NO demo/mock data

- ✅ All KPIs in `/admin/fleet/` are live DB-derived (`FleetChrNode`, `FleetChrHealth`, `FleetChrMetric`).
- ✅ Onboarding wizard creates real rows.
- ✅ Front-door page is fully real (encrypted token, real preview/apply).
- ✅ No "lorem ipsum" / placeholder strings rendered as live.

---

## J. SUMMARY / PRIORITY DISPATCH LIST

### 🔴 HIGH — owner-rule violations (do first)

1. **Replace `SERVICES_MOCK`** with real `ServiceCatalogItem` + per-service usage counters fed by the customer radius. → §A row 1.
2. **Wire `/settings/admins`** — four POST handlers for create/edit/enable-disable/delete. → §B row 1.
3. **Wire `/settings/whatsapp`** OR delete the duplicate page. → §B row 2.
4. **Wire `/settings` general-info forms** (site_name, logo, …). → §B row 3.
5. **Server-enforce section hide** — `before_request` guard returns 404 on hidden endpoints. → §F.1.
6. **Customer-blocked → bridge-deny** — add `customer.status` check in `_checked_license_from_integration_body()`. → §G.1.

### 🟠 MED — quality / operational

7. Move env-only operational tunables (CHR PPP pool, IPsec extras, rate-limit knobs, fleet thresholds) into UI-editable `Setting` rows with env fallback. → §D.2.
8. Surface scheduled-task status (whatsapp-drain, chr-metrics, vpn-quota-sync, enforce-allocations) — UI list with last-run + "run now". → §D.3.
9. Promote sensitive routes to `@super_admin_required` (payment approve/reject, license revoke, customer status flip). → §F.2.
10. Wire fleet `_notify_hook` to messaging layer (Phase-9). → §I.1 row 1.

### 🟡 LOW — cosmetic

11. Update fleet UI source banner so it consistently reads "المنسّق الفعلي" / "المخّ الفعلي" now that real impls are wired. → §I row last.
12. Add UI READ-only "configured ✓" indicators for the truly env-only secrets (LICENSE_CHECK_HMAC_SECRET, RADIUS_PROXY_SHARED_SECRET, WHATSAPP_FERNET_KEY) so the operator can verify without shell access. → §D.1.
13. Catalog metadata editor (icons, descriptions) for `ServiceCatalogItem`. → §A row 2.

### NEEDS-OWNER-INPUT
- §A row 1: contract shape for per-service usage telemetry from customer radius.
- §C row 2: target SMS gateway provider.
- §F.2: confirm RBAC tier per sensitive route (operator vs super).

---

**End of inventory.** No source files were modified during this audit.
