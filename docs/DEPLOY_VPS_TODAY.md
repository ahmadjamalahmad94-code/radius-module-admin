# VPS Launch Note

This repo is the standalone HobeRadius License Control Panel. It sells and signs commercial entitlements; customer RADIUS installations enforce the returned contract locally.

## Required Environment

Set these before production boot:

```env
LICENSE_PANEL_ENV=production
FLASK_DEBUG=0
FLASK_SECRET=replace-with-a-long-random-flask-secret
DATABASE_URL=postgresql+psycopg://license_user:replace-password@127.0.0.1:5432/license_panel
LICENSE_ADMIN_USERNAME=admin
LICENSE_ADMIN_PASSWORD=replace-with-a-strong-unique-admin-password
LICENSE_ADMIN_EMAIL=admin@example.com
DEFAULT_GRACE_DAYS=7
DEFAULT_CURRENCY=USD
SUPPORT_EMAIL=support@example.com
SUPPORT_PHONE=+0000000000
AUTO_INIT_DB=0
RATE_LIMITS_ENABLED=1
LICENSE_CHECK_HMAC_SECRET=replace-with-a-long-random-license-check-secret
LICENSE_CHECK_SIGNATURE_REQUIRED=1
LICENSE_CHECK_ALLOW_UNSIGNED=0
TRUST_PROXY_HEADERS=1
SESSION_COOKIE_SECURE=1
SESSION_COOKIE_SAMESITE=Lax
SESSION_LIFETIME_SECONDS=43200
LOG_LEVEL=INFO
```

Keep the full template at `deploy/env/license-panel.env.example` as the source of optional rate-limit and replay-window tuning values.

## Temporary IP Bootstrap

If the VPS is still reachable only by raw IP over HTTP, use bootstrap mode for
the first login only:

```env
LICENSE_PANEL_ENV=bootstrap
FLASK_DEBUG=0
FLASK_SECRET=replace-with-a-long-random-flask-secret
DATABASE_URL=postgresql+psycopg://license_user:replace-password@127.0.0.1:5432/license_panel
LICENSE_ADMIN_USERNAME=admin
LICENSE_ADMIN_PASSWORD=replace-with-a-strong-unique-admin-password
LICENSE_ADMIN_EMAIL=admin@example.com
AUTO_INIT_DB=0
RATE_LIMITS_ENABLED=1
LICENSE_CHECK_HMAC_SECRET=replace-with-a-long-random-license-check-secret
LICENSE_CHECK_SIGNATURE_REQUIRED=1
LICENSE_CHECK_ALLOW_UNSIGNED=0
TRUST_PROXY_HEADERS=1
SESSION_COOKIE_SECURE=0
SESSION_COOKIE_SAMESITE=Lax
SESSION_LIFETIME_SECONDS=43200
LOG_LEVEL=INFO
```

Bootstrap mode keeps CSRF, strong secrets, non-default admin password, signed
license checks, and debug-off validation. It only allows `SESSION_COOKIE_SECURE=0`
so browser session cookies work at `http://<server-ip>/login`.

After the domain and HTTPS are ready, switch back to:

```env
LICENSE_PANEL_ENV=production
SESSION_COOKIE_SECURE=1
LICENSE_CHECK_SIGNATURE_REQUIRED=1
LICENSE_CHECK_ALLOW_UNSIGNED=0
```

Do not use bootstrap mode for final production traffic.

## Install And Initialize

Use the existing deploy layout from `deploy/README.md`:

```bash
cd /opt/hoberadius-license-panel
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -r requirements-production.txt
```

Run database initialization once after loading the environment:

```bash
set -a
. /etc/hoberadius-license-panel/license-panel.env
set +a
.venv/bin/flask --app wsgi init-db
```

This project currently uses SQLAlchemy `create_all()` through `flask --app wsgi init-db`; running it after this release creates the new VPN entitlement tables without dropping existing tables.

## Run App

Recommended first VPS command:

```bash
/opt/hoberadius-license-panel/.venv/bin/gunicorn "wsgi:app" \
  --bind 127.0.0.1:5055 \
  --workers 1 \
  --access-logfile - \
  --error-logfile -
```

The existing systemd example is `deploy/systemd/hoberadius-license-panel.service.example`.

## Reverse Proxy

Use the existing Nginx example at `deploy/nginx/hoberadius-license-panel.conf.example`, enable HTTPS, and forward `X-Forwarded-For` and `X-Forwarded-Proto`. Keep `TRUST_PROXY_HEADERS=1` only behind trusted Nginx.

## Backup

PostgreSQL is recommended for commercial production:

```bash
pg_dump --format=custom --file=/var/backups/hoberadius-license-panel/license-panel-$(date +%F).dump "$DATABASE_URL"
```

For small SQLite trials only, use:

```bash
.venv/bin/python deploy/scripts/backup_sqlite.py \
  /opt/hoberadius-license-panel/instance/license_panel.sqlite3 \
  /var/backups/hoberadius-license-panel
```

## Smoke Test Checklist

- `GET /api/health` returns `{"ok": true, "status": "healthy"}`.
- Admin login/logout work over HTTPS.
- `/admin/vpn-services` renders and default VPN packages exist after `init-db`.
- `/admin/customers/<id>/vpn-service` can activate, suspend, and disable `ip_change_vpn`.
- Signed `POST /api/license/check` still returns the original license fields.
- Active VPN customers receive `services.ip_change_vpn.enabled=true`.
- Suspended, revoked, expired, or denied licenses never receive an active VPN entitlement.
- `LICENSE_CHECK_ALLOW_UNSIGNED=0` and `LICENSE_CHECK_SIGNATURE_REQUIRED=1` in production.
- `LICENSE_PANEL_ENV=production` and `SESSION_COOKIE_SECURE=1` after domain/TLS are active.
- Backups are configured and restore-tested.
