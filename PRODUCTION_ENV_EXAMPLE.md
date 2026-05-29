# Production Environment Example

Do not copy these values blindly. Use this as a template and replace every
placeholder with a real production value.

Do not commit a real `.env` file.

## Required Production Variables

```env
# Required: production enables startup safety checks.
LICENSE_PANEL_ENV=production
FLASK_DEBUG=0

# Required: long random secret. Never use dev-secret-change-me or change-this-secret.
FLASK_SECRET=replace-with-a-long-random-secret-at-least-32-bytes

# Required: use PostgreSQL for real production when possible.
# Example:
DATABASE_URL=postgresql+psycopg://license_user:replace-password@127.0.0.1:5432/license_panel

# SQLite can be used only for a small single-process temporary deployment.
# DATABASE_URL=sqlite:////opt/hoberadius-license-panel/instance/license_panel.sqlite3

# Required: initial admin account used by the seed process.
LICENSE_ADMIN_USERNAME=admin
LICENSE_ADMIN_PASSWORD=replace-with-a-strong-unique-password
LICENSE_ADMIN_EMAIL=admin@example.com

# Required business defaults.
DEFAULT_GRACE_DAYS=7
DEFAULT_CURRENCY=USD
SUPPORT_EMAIL=support@example.com
SUPPORT_PHONE=+0000000000

# Production choice:
# 1 = create tables and seed default admin/plans on startup.
# 0 = do not auto-create; use an explicit migration/init process.
AUTO_INIT_DB=0

# Built-in first-version rate limits.
RATE_LIMITS_ENABLED=1
LOGIN_RATE_LIMIT_MAX=10
LOGIN_RATE_LIMIT_WINDOW_SECONDS=900
LICENSE_CHECK_RATE_LIMIT_MAX=120
LICENSE_CHECK_RATE_LIMIT_WINDOW_SECONDS=60
LICENSE_KEY_RATE_LIMIT_MAX=600
LICENSE_KEY_RATE_LIMIT_WINDOW_SECONDS=300

# Signed license checks.
# Use the same secret in customer RADIUS installations that call /api/license/check.
LICENSE_CHECK_HMAC_SECRET=replace-with-a-long-random-license-check-signing-secret
LICENSE_CHECK_SIGNATURE_REQUIRED=1
LICENSE_CHECK_ALLOW_UNSIGNED=0
LICENSE_CHECK_MAX_CLOCK_SKEW_SECONDS=300
LICENSE_CHECK_REPLAY_WINDOW_SECONDS=600
LICENSE_CHECK_NONCE_CACHE_MAX=5000

# Reverse proxy and session safety.
# Set TRUST_PROXY_HEADERS=1 only when the app is behind a trusted proxy such as Nginx.
TRUST_PROXY_HEADERS=1
SESSION_COOKIE_SECURE=1
SESSION_COOKIE_SAMESITE=Lax
SESSION_LIFETIME_SECONDS=43200

# Operational logging.
LOG_LEVEL=INFO
```

## Temporary IP-Only Bootstrap Mode

Use this only for first login over a raw VPS IP before the domain and TLS are
ready. CSRF remains enabled, debug remains disabled, and all production
password/signing secret checks still run. The only relaxed setting is the secure
session cookie because browsers do not send `Secure` cookies over plain HTTP.

Temporary values:

```env
LICENSE_PANEL_ENV=bootstrap
FLASK_DEBUG=0
FLASK_SECRET=replace-with-a-long-random-secret-at-least-32-bytes
DATABASE_URL=postgresql+psycopg://license_user:replace-password@127.0.0.1:5432/license_panel
LICENSE_ADMIN_USERNAME=admin
LICENSE_ADMIN_PASSWORD=replace-with-a-strong-unique-password
LICENSE_ADMIN_EMAIL=admin@example.com
AUTO_INIT_DB=0
RATE_LIMITS_ENABLED=1
LICENSE_CHECK_HMAC_SECRET=replace-with-a-long-random-license-check-signing-secret
LICENSE_CHECK_SIGNATURE_REQUIRED=1
LICENSE_CHECK_ALLOW_UNSIGNED=0
TRUST_PROXY_HEADERS=1
SESSION_COOKIE_SECURE=0
SESSION_COOKIE_SAMESITE=Lax
SESSION_LIFETIME_SECONDS=43200
LOG_LEVEL=INFO
```

After the domain and HTTPS are working, switch back to:

```env
LICENSE_PANEL_ENV=production
SESSION_COOKIE_SECURE=1
LICENSE_CHECK_SIGNATURE_REQUIRED=1
LICENSE_CHECK_ALLOW_UNSIGNED=0
```

Do not keep bootstrap mode enabled for real production traffic.

## Forbidden Values

Production must never use:

```env
LICENSE_PANEL_ENV=local
LICENSE_PANEL_ENV=bootstrap
FLASK_SECRET=dev-secret-change-me
FLASK_SECRET=change-this-secret
LICENSE_ADMIN_PASSWORD=admin12345
LICENSE_ADMIN_PASSWORD=change-this-password
```

The app refuses to start in `production` or `bootstrap` when built-in default
secrets, placeholder secrets, or the default admin password are still active.

## Minimal Local Demo Env

For local demo only:

```env
LICENSE_PANEL_ENV=local
FLASK_SECRET=change-this-secret
DATABASE_URL=sqlite:///license_panel.sqlite3
LICENSE_ADMIN_USERNAME=admin
LICENSE_ADMIN_PASSWORD=admin12345
LICENSE_ADMIN_EMAIL=admin@example.com
AUTO_INIT_DB=1
RATE_LIMITS_ENABLED=1
LICENSE_CHECK_SIGNATURE_REQUIRED=0
LICENSE_CHECK_ALLOW_UNSIGNED=1
TRUST_PROXY_HEADERS=0
SESSION_COOKIE_SECURE=0
```

Run:

```powershell
cd "C:\Users\Ahmad J Ahmad\Desktop\hub\radius-module-admin"
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python run.py
```

Open:

```text
http://127.0.0.1:5055/login
```

## Customer License Check Contract

Customer RADIUS installations should call:

```text
POST https://license.example.com/api/license/check
```

Example:

```python
import hashlib
import hmac
import json
import time
import uuid

import requests

license_check_secret = "same-secret-configured-on-license-panel"
payload = {
    "license_key": "HBR-2026-ABCD-EFGH-9K22",
    "server_fingerprint": "server-fingerprint-hash",
    "hostname": "client-vps-1",
    "version": "1.0.0",
    "install_id": "optional-install-id",
    "domain": "radius.customer.example",
    "timestamp": int(time.time()),
    "nonce": str(uuid.uuid4()),
}

canonical = json.dumps(
    {key: value for key, value in payload.items() if key != "signature"},
    ensure_ascii=False,
    separators=(",", ":"),
    sort_keys=True,
)
payload["signature"] = hmac.new(
    license_check_secret.encode("utf-8"),
    canonical.encode("utf-8"),
    hashlib.sha256,
).hexdigest()

response = requests.post(
    "https://license.example.com/api/license/check",
    json=payload,
    timeout=10,
)
license_state = response.json()

if license_state["mode"] == "active":
    # Allow normal operations.
    pass
elif license_state["mode"] == "limited":
    # Allow admin login/read-only views, block new users/cards/sync actions.
    pass
else:
    # Denied: block sensitive operations and show support contact.
    pass
```

The public API must not receive admin credentials. It only needs the license
key, server fingerprint, and optional server metadata.

Production requires signed requests by default. Unsigned compatibility mode is
for local/staging or controlled rollout only.

## Nginx And TLS Reminder

- Serve production through HTTPS only.
- Terminate TLS in Nginx or another reverse proxy.
- Forward `Host`, `X-Real-IP`, `X-Forwarded-For`, and `X-Forwarded-Proto`.
- Set `TRUST_PROXY_HEADERS=1` only after the Flask app is reachable only from
  the trusted proxy.
- Do not expose Flask's development server directly.

## WSGI Entrypoint

Use the production WSGI module:

```bash
python -m pip install -r requirements-production.txt
gunicorn "wsgi:app" --bind 127.0.0.1:5055 --workers 1
```

Do not run `python run.py` for production service hosting.

## Backup Reminder

- Back up the database daily.
- Keep at least one off-server backup.
- Test restore regularly.
- Back up the deployment env file through a secret manager or secure server
  backup, not through Git.

## Multi-Worker Rate Limit TODO

The current limiter is in-memory. Before using multiple Gunicorn workers,
multiple servers, or container replicas, move rate limit state to Redis or
another shared store.
