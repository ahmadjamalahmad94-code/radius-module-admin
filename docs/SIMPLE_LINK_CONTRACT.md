# تبسيط ربط الريدياس ↔ لوحة التراخيص — تحقيق + عقد التبسيط
**Status:** DESIGN (no code changed) · **Date:** 2026-06-11 · **Scope:** radius-module-admin (server) + radius-module (client) + radius-proxy (bystander)

> هدف المالك: «مفتاح الترخيص وحده يكفي» — يعرّف حدود المشترك، يربط الريدياس باللوحة،
> يربط بصفحته الشخصية، ويسهّل رفع النسخ الاحتياطية. بدون مفتاح+مفتاح+سر+بصمة+ختم.

---

## 1) خريطة المصافحة الحالية (كل الاعتمادات، بالأدلة)

The customer radius (radius-module) calls the panel **directly over HTTPS** — the
radius-proxy is NOT in this path (see §2). Every bridge call today carries up to
**five** credential artefacts:

| # | Credential | Generated where | Checked where (panel) | Failure code |
|---|-----------|-----------------|----------------------|--------------|
| 1 | **License key** `HBR-YYYY-…` | `app/services/license_service.py:67-76` (`generate_license_key`) | `check_license` `app/services/license_service.py:112-195` (resolve + status/expiry) | 404/`not_found`, 403 via handlers when `not result.active` |
| 2 | **HMAC signature** (`signature` + `timestamp` + `nonce`) | client signs canonical JSON: `radius-module app/radius/services/admin_panel_client.py:1049-1064` | `verify_license_signature` `app/license_signing.py:71-124` — accepts **root** `LICENSE_CHECK_HMAC_SECRET`, **derived per-license secret**, or **rotatable bridge token** (3 candidate secrets!) | **401** `denied` |
| 3 | **Shared secret «سر الربط»** = `license_integration_secret` = HMAC(root, `"hoberadius-license-integration:KEY"`) — **derived, stored nowhere** | `app/license_signing.py:62-68` | (a) as HMAC key (above); (b) verbatim header/body for backups: `verify_instance_secret` `app/services/customer_backups.py:47-72` | **401** `denied` (`customer_backups.py:94`) |
| 4 | **Activation/bind code «كود التفعيل»** (one-time) | admin UI `app/admin/routes.py:4106-4122` (`InstanceActivationToken`) | `/api/integration/hoberadius/instance/activate` `app/api/routes.py:1094-1199` — exchanges code → returns license_key + shared_secret | 401/409/410 |
| 5 | **server_fingerprint** | client auto-computes (radius-module `license_file.html:516-523`, env `HOBERADIUS_SERVER_FINGERPRINT`) | **required-present** (422 if missing: `app/api/routes.py:70-76`, `:1043-1044`); slot/rotation logic `license_service.py:156-184` — **non-blocking by default**, hard-deny only with `LICENSE_FINGERPRINT_STRICT=1` | 422 missing; 403-ish denial only in strict mode |
| — | **Bridge token (rotatable)** | `app/services/bridge_token_sync.py` (delivered inside runtime-contract: `customer_control.py:1070-1095`; reverse report: `app/api/bridge_token_routes.py:109-176`) | accepted as 3rd signing secret `license_signing.py:127-162` | — |
| — | **X-Proxy-Token / `RADIUS_PROXY_SHARED_SECRET`** | proxy agent (`radius-proxy/proxy_auth.py:26-49`) | **panel↔proxy only**: `app/api/proxy_api.py:40-93` guards `/api/proxy/*` | 401 — **never touches the licensing path** |

**The exact 403 sites in the panel (the only ones on the bridge path):**

1. `app/api/routes.py:1070-1075` — **customer-status gate**: `customer.status ∈ {"blocked","inactive","pending"}` → `403 customer_blocked / customer_pending`. Runs inside `_checked_license_from_integration_body`, i.e. on **every** integration endpoint.
2. `app/api/routes.py:171, 218, 270, 277, 715` — `not result.active` → `403 "الترخيص ليس نشطًا"` (license suspended/revoked/expired-out-of-grace, or strict-fingerprint denial).

Everything signature-related returns **401**, not 403. HTTPS violations return **426**.

**The «سر الربط» the owner couldn't find:** it is **derived, never stored**, and surfaced in
exactly ONE place — the customer's **portal dashboard** («سر التوقيع»,
`app/templates/public/customer_portal_dashboard.html:1247`, built in `app/public/routes.py:1227-1243`).
It is NOT shown anywhere in the admin customer page. The intended path was the activation
code flow (#4) which delivers it automatically; if that flow isn't used, the owner has to
find a secret that effectively "doesn't exist anywhere". His complaint is fully justified.

---

## 2) لماذا «دخل الوكيل فخرب الربط» — الانحدار مثبَّت

**radius-proxy is exonerated as a path element**: it is a pure **UDP RADIUS relay**
(listens 1812/1813 only; `radius-proxy/proxy.py:422-451`), has **zero HTTP listeners**, and
is only an outbound HTTPS *client* of `/api/proxy/*`. It cannot return 403 to the
radius-module licensing flow because it never sees that traffic.

What actually happened around the proxy rollout (three contemporaneous causes):

1. **Header stripping by the web tier (401):** backups/upload authenticates by the verbatim
   secret in header `X-HobeRadius-Admin-Secret` (`customer_backups.py:47-72`). The proxy-era
   VPS re-plumbing (reverse-proxy/TLS tier) stripped custom headers → **401**. Fixed
   client-side in radius-module commit `88208d7` ("send integration secret in body too —
   proxy strips header → 401"); panel already accepts body fallback (`app/api/routes.py:334-336`).
2. **Customer-status gate (403):** the `_BRIDGE_BLOCKED_CUSTOMER_STATUSES` gate
   (`routes.py:1020-1030`, "FIX #5") landed in the same era. Any customer left `pending`
   (or set `inactive/blocked`) suddenly got **403 on every bridge endpoint** — even with a
   perfectly valid license + signature. This matches "started failing with 403" precisely.
3. **DB split-brain (resolved separately):** during the same window the panel briefly ran
   against the wrong SQLite file (systemd `DATABASE_URL` issue), so licenses/customers
   resolved as missing/pending → 403/404 storms. Fixed in the db-unify work.

**Conclusion:** the 403 was never a missing *proxy* credential. It was the panel's own
customer-status gate (+ transient wrong-DB), and a separate 401 from header stripping. The
five-credential design made it impossible for the owner to tell which artefact failed.

---

## 3) ما الغرض الأمني الحقيقي لكل عنصر — وماذا يمكن حذفه

| Artefact | Real purpose | Verdict for license-key-only |
|----------|-------------|------------------------------|
| License key | Identity + entitlement lookup | **KEEP — becomes THE bearer credential** |
| HMAC signature + timestamp + nonce | Proves possession of a secret without sending it; replay protection | **DROP (as a requirement).** Over mandatory HTTPS (already enforced, 426) the body is confidential; and since the *license key already travels in every signed body*, the signature adds no secrecy the key doesn't have. Replay protection of a bearer token is moot — whoever holds the key can mint fresh requests anyway. Honest loss: none material, **provided the license key is treated as a secret** (maskable, rotatable). |
| Derived shared secret «سر الربط» | The HMAC key | **DROP.** Its only job was to key #2. |
| Activation code | Bootstrap delivery of the derived secret | **DROP.** Nothing left to deliver — the owner already has the license key. |
| Rotatable bridge token | Rotation story for the HMAC secret | **RETIRE from the auth path** (keep the table dormant). Rotation = reissue/regenerate the license key from the admin panel (rare, owner-driven, single artefact). |
| server_fingerprint | Per-instance identity / anti-sharing | **MAKE OPTIONAL (auto, informational).** Already non-blocking by default with slot rotation (`license_service.py:156-184`). Client auto-computes and sends it silently; the panel records it (TOFU pinning + visibility on the customer page); `LICENSE_FINGERPRINT_STRICT=1` stays as the opt-in hard lock. The 422 "fingerprint required" checks are relaxed. |
| X-Proxy-Token | panel↔proxy ingest auth | **UNCHANGED** — different channel entirely. |

**Can the license key alone authenticate the link? Yes, honestly:** it is a 16-char
high-entropy string from a 36-symbol alphabet (~82 bits), transmitted only over HTTPS,
resolvable in O(1), and constant-time comparable. That is a standard API-bearer-token
posture. What we genuinely lose vs HMAC: a stolen *request log* would expose the credential
— but today's signed bodies **already contain the license key**, and the backup channel
already sends the raw secret verbatim, so the practical delta is ~zero. Mitigations kept:
mandatory HTTPS (426), never log the key (mask to `HBR-…-6789`), TOFU instance pinning,
owner-side regenerate button.

---

## 4) العقد المبسّط — «مفتاح الترخيص هو كل شيء»

### Auth (one rule, all bridge endpoints)
```
POST https://<panel>/api/integration/hoberadius/<endpoint>
Authorization: Bearer HBR-2026-XXXX-XXXX-XXXX        ← preferred
Content-Type: application/json

{ "license_key": "HBR-2026-XXXX-XXXX-XXXX", ... }   ← body copy REQUIRED
```
- The **body `license_key` is authoritative** (header-strip-proof — lesson of `88208d7`).
  The `Authorization` header is sent for hygiene/log-tooling but never required.
- HTTPS mandatory (existing 426 guard unchanged).
- `server_fingerprint`, `hostname`, `version`, `install_id` become **optional** informational
  fields (client auto-fills; absence is no longer 422).
- `signature/timestamp/nonce` become **optional**: if present they're verified (old clients
  keep working); if absent, bearer mode applies. Policy knob
  `LICENSE_BEARER_AUTH_ENABLED` (Setting, default **on**) lets the owner force-require
  signatures again if ever needed.

### Server-side validation order (single chokepoint)
1. HTTPS? else 426.
2. Resolve `License` by body `license_key` (constant-time compare on the keyed lookup
   result). Unknown → 404 `not_found`.
3. License status/expiry via existing `check_license` (unchanged semantics: active / grace
   / expired / suspended).
4. Customer-status gate (unchanged) → 403 `customer_blocked|customer_pending` **with a
   clear Arabic reason naming the customer status** (the error body already does this).
5. Record fingerprint if sent (TOFU + rotation, unchanged); strict mode unchanged.

### Response envelope (unchanged shapes)
All existing contracts (runtime-contract, capacity, identity-sync, backups, …) keep their
response bodies. The `bridge_token` block inside runtime-contract remains for back-compat
but is no longer needed by new clients.

### Backups (same single key)
```
POST /api/integration/hoberadius/backups/upload
{ "license_key": "HBR-…", "backup_reference": "...", "checksum_sha256": "...",
  "size": 12345, "kind": "sqlite", "content_base64": "..." }
```
`verify_instance_secret` accepts the **license key itself** as the credential (legacy
`admin_secret`/header still accepted). 401 only when the key doesn't resolve.

### Customer-page linking (the owner's UX ask)
Admin customer page gets one **«ربط الريدياس»** card: the license key + copy button +
"regenerate key" (rotation) + the list of instances seen (fingerprint, hostname, last_seen
— data already in `LicenseCheck`). On the radius side the setup form collapses to **two
fields**: panel URL + license key. Paste → test → linked; same key powers contracts,
identity-sync, his portal page (SSO endpoint unchanged), and backups.

---

## 5) قائمة التغييرات عبر المستودعات (مواصفة لثلاثة وكلاء تنفيذ متوازيين)

### A) radius-module-admin (server) — the authority
1. `app/license_signing.py` — add bearer mode to `verify_license_signature` (or a thin
   `verify_bridge_auth(app, body)` wrapper): no signature + `LICENSE_BEARER_AUTH_ENABLED`
   → resolve license by `body["license_key"]`; signature present → existing path verbatim.
2. `app/api/routes.py` — relax the two `fingerprint` 422 requirements
   (`:70-76`, `:1043-1044`) to optional-empty; keep everything else.
3. `app/services/customer_backups.py:47-72` — `verify_instance_secret`: accept the
   license key itself (constant-time) alongside the two legacy secrets.
4. Settings: new `LICENSE_BEARER_AUTH_ENABLED` (default on) in platform settings UI.
5. Admin customer page: «ربط الريدياس» card (key + copy + regenerate + instances list).
   Regenerate = new key + old key grace window (24h) so a running instance can re-sync.
6. Logging hygiene: mask license keys in new log lines (`HBR-…-6789` style).
7. Tests: bearer happy-path per endpoint; signature back-compat; pending-customer 403
   body clarity; backups with key-as-secret.

### B) radius-module (client)
1. `app/radius/services/admin_panel_client.py` — when no `shared_secret` configured, send
   bearer style (body `license_key` + `Authorization` header), skip signing; keep signing
   when a secret IS configured (zero-downtime back-compat).
2. Setup UI `license_file.html` — collapse to: panel URL + license key (+ optional
   advanced accordion: fingerprint override, legacy secret). Remove activation-code +
   secret from the main flow.
3. Auto-fingerprint silently (existing logic), send informationally.
4. Backups: stop requiring `HOBERADIUS_ADMIN_SHARED_SECRET`; key in body suffices.
5. Error UX: map 403 `customer_pending/customer_blocked` to a clear Arabic banner ("حساب
   العميل بانتظار التفعيل في لوحة التراخيص") — the original confusion's antidote.

### C) radius-proxy
**No changes required.** It is not in the licensing path (UDP-only relay; HTTP client of
`/api/proxy/*` with its own `X-Proxy-Token`). Only guardrail: never route or NAT panel
`/api/integration/*` through it in deployment docs.

### Migration order
A ships first (server accepts both modes) → B ships (clients go bearer) → later, owner may
flip `LICENSE_BEARER_AUTH_ENABLED`-only posture and we delete the signing machinery + the
activation-code + bridge-token sync code (≈1,000 LoC retired across both repos).
