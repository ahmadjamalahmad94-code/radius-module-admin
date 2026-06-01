# Customer Secure Vault — الخزنة الخاصة بالعميل

A secure, **admin-only** store attached to each customer in the HobeRadius license
panel (`radius-module-admin`). It holds private operational data and encrypted access
secrets so you never keep customer VPS links, passwords, API tokens, MikroTik access,
or backup credentials in external files.

> **It is never visible to the customer, never in the customer portal, never in public
> pages, and never returned by customer/integration APIs.**

---

## Purpose

- Keep per-customer operational notes/links (VPS URL, RADIUS URL, server IP, deployment
  & handover notes) in one admin-only place.
- Keep sensitive secrets (passwords, SSH keys, DB passwords, API tokens, backup secrets)
  **encrypted at rest**, revealed only by a deliberate, audited admin action.

## Two data types

1. **Private records** (`customer_private_records`) — admin-only, *not* secrets
   (links, notes, IPs, dates). Plain text in the DB; admin-only by access control.
2. **Encrypted secrets** (`customer_secret_vault`) — passwords/keys/tokens. The value is
   stored **Fernet-encrypted** in `encrypted_secret`; plaintext is never persisted.

A dedicated audit table (`customer_vault_audit_logs`) records every vault action.

## What to store / what NOT to store

- **Store:** VPS/RADIUS URLs, server IP, provider, setup/handover notes; and secrets like
  VPS/SSH/DB/MikroTik passwords, SSH private keys, Google Drive/WhatsApp/API/backup secrets.
- **Do NOT store:** anything the customer should see, or data you are not authorized to keep.
  Do not paste secrets into the *private records* tab — use the *secrets* tab (encrypted).

## Permission model

The panel has no granular roles, only `Admin.is_super_admin`. Conservative mapping:

| Capability | Who |
|---|---|
| View vault, private records, **secret metadata** | any active admin |
| Create / update / archive **private records** | any active admin |
| Create / update / rotate / **reveal** / archive **secrets** | **super admin only** |
| Customer / portal / public / integration API | **no access** |

The bootstrap/primary admin (`LICENSE_ADMIN_USERNAME`) is auto-promoted to super admin so
the owner can use the vault immediately. Promote others by setting `admins.is_super_admin`.

Every route checks permission **server-side** (`@login_required` / `@super_admin_required`),
not just via UI hiding.

## Encryption model

- Library: `cryptography` Fernet (AES-128-CBC + HMAC-SHA256). No custom crypto.
- Helpers: `app/services/customer_vault_crypto.py` — `encrypt_secret`, `decrypt_secret`,
  `mask_secret`, `encryption_available`.
- Plaintext is encrypted on create/rotate and only decrypted by `reveal_secret()`.
- Secret values never appear in list responses, page source, logs, or audit metadata.

## Environment variable

```
CUSTOMER_VAULT_ENCRYPTION_KEY=<fernet-key>
```

Generate a key:

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Rules:
- The key comes from the **environment only** — never stored in the DB, never committed.
- If missing/invalid: the vault page still loads, but creating/revealing secrets is blocked
  with: «مفتاح تشفير الخزنة غير مضبوط. لا يمكن حفظ أو عرض الأسرار.» The rest of the panel is unaffected.

## Reveal / copy & audit behavior

- Secrets are masked/hidden by default; the value is **not** in the page on load.
- Revealing requires clicking **عرض السر**, confirming in a modal (with an optional reason).
- The plaintext is fetched via `POST .../secrets/<id>/reveal` (JSON only, super-admin only)
  and shown in a temporary field; it is **not** stored in localStorage/sessionStorage and is
  cleared when the modal closes. It does not survive a page refresh.
- **Reveal and rotate/create/archive are always audited** in `customer_vault_audit_logs`
  (actor, action, target, IP, user-agent, optional reason) — never the secret value.

## How to rotate secrets

Open the secret card → **تدوير** → paste the new value → save. The old ciphertext is
replaced, `last_rotated_at` is updated, and a `secret_rotated` audit row is written.

## Backup & restore

- DB backups include the vault tables, but secrets are **encrypted at rest**, so backups
  never contain plaintext. There is no decrypted CSV/Excel export of secrets.
- The customer backup summary (`_SUMMARY_TABLES`) is a hard-coded allow-list and does **not**
  include vault tables.
- **⚠️ If you lose `CUSTOMER_VAULT_ENCRYPTION_KEY`, saved vault secrets cannot be decrypted.**
  Restoring a backup requires the *same* key that encrypted those rows.

## Customer-exposure guarantees (verified)

- No code in `app/public/` or `app/api/` references the vault models.
- The `Customer` model has no generic `to_dict`; all customer/portal/API serializers list
  fields explicitly, so new vault tables/columns are never auto-included.
- Tests assert plaintext never appears in create/list responses, audit metadata, or the
  vault page HTML, and that the customer portal contains no vault data.

## Files

- Models: `app/models.py` (`CustomerPrivateRecord`, `CustomerSecret`, `CustomerVaultAuditLog`,
  `Admin.is_super_admin`)
- Crypto: `app/services/customer_vault_crypto.py`
- Service: `app/services/customer_vault.py`
- Routes: `app/admin/vault_routes.py` (blueprint `admin_vault`, `/admin/customers/<id>/vault`)
- Permission decorator: `app/auth/routes.py` (`super_admin_required`)
- UI: `app/templates/admin/customer_vault.html`, `static/css/customer_vault.css`,
  `static/js/customer_vault.js`; link from `admin/customer_detail.html`
- Tests: `tests/test_customer_vault.py`

## Troubleshooting

- **"لا يمكن حفظ أو عرض الأسرار"** → `CUSTOMER_VAULT_ENCRYPTION_KEY` is unset or invalid.
- **Reveal fails / "Invalid or tampered vault secret"** → the key differs from the one used
  to encrypt (e.g. restored a backup with a different key).
- **Vault button/route 404** → deploy the latest code and run `flask init-db` once (creates
  the new tables + the `is_super_admin` column), then restart the service.
- **Admin can view metadata but not reveal** → that admin is not a super admin.
