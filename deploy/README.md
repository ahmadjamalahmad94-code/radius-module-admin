# Single VPS Deployment Guide

This guide is for one Linux VPS running the standalone HobeRadius License
Control Panel.

It does not deploy the customer RADIUS app.

## Layout

Recommended paths:

```text
/opt/hoberadius-license-panel        application checkout
/opt/hoberadius-license-panel/.venv  Python virtual environment
/etc/hoberadius-license-panel        environment file
/var/backups/hoberadius-license-panel backups
```

## Install

```bash
sudo useradd --system --home /opt/hoberadius-license-panel --shell /usr/sbin/nologin licensepanel
sudo mkdir -p /opt/hoberadius-license-panel /etc/hoberadius-license-panel /var/backups/hoberadius-license-panel
sudo chown -R licensepanel:licensepanel /opt/hoberadius-license-panel /var/backups/hoberadius-license-panel
```

Copy the project into `/opt/hoberadius-license-panel`, then install:

```bash
cd /opt/hoberadius-license-panel
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -r requirements-production.txt
```

Create the environment file:

```bash
sudo install -m 600 deploy/env/license-panel.env.example /etc/hoberadius-license-panel/license-panel.env
sudo editor /etc/hoberadius-license-panel/license-panel.env
```

Replace every placeholder secret before starting the service.

## First Database Setup

Run this once after the environment file is complete:

```bash
cd /opt/hoberadius-license-panel
set -a
. /etc/hoberadius-license-panel/license-panel.env
set +a
.venv/bin/flask --app wsgi init-db
```

`init-db` creates tables, sample plans/settings, and the first admin when no
admin exists. Use `flask --app wsgi bootstrap-admin` only if a database already
has tables but no admin account.

## Gunicorn

Recommended command for the first single-process deployment:

```bash
/opt/hoberadius-license-panel/.venv/bin/gunicorn "wsgi:app" \
  --bind 127.0.0.1:5055 \
  --workers 1 \
  --access-logfile - \
  --error-logfile -
```

Keep `--workers 1` until rate limiting and nonce replay state are moved to a
shared store such as Redis.

## systemd

Install the example service:

```bash
sudo cp deploy/systemd/hoberadius-license-panel.service.example /etc/systemd/system/hoberadius-license-panel.service
sudo systemctl daemon-reload
sudo systemctl enable --now hoberadius-license-panel
sudo systemctl status hoberadius-license-panel
```

Logs:

```bash
journalctl -u hoberadius-license-panel -f
```

## Nginx And TLS

Install the example site and edit the domain:

```bash
sudo cp deploy/nginx/hoberadius-license-panel.conf.example /etc/nginx/sites-available/hoberadius-license-panel
sudo ln -s /etc/nginx/sites-available/hoberadius-license-panel /etc/nginx/sites-enabled/hoberadius-license-panel
sudo nginx -t
sudo systemctl reload nginx
```

Use Certbot or your normal certificate tooling:

```bash
sudo certbot --nginx -d license.example.com
```

## Health Checks

Local process check:

```bash
.venv/bin/python deploy/scripts/health_check.py http://127.0.0.1:5055
```

External HTTPS check:

```bash
.venv/bin/python deploy/scripts/health_check.py https://license.example.com
```

## License Check Smoke Test

Use an existing license key and the signing secret configured on the server.
The customer RADIUS app should call `POST /api/license/check` with a timestamp,
unique nonce, and HMAC-SHA256 signature.

Expected production modes:

- `active`: normal operations allowed.
- `limited`: admin/read-only views allowed, new users/cards/sync blocked.
- `denied`: sensitive operations blocked.

## SQLite Backup

SQLite is acceptable only for demos, single-process trials, or very small
installations.

Create a safe SQLite backup:

```bash
.venv/bin/python deploy/scripts/backup_sqlite.py \
  /opt/hoberadius-license-panel/instance/license_panel.sqlite3 \
  /var/backups/hoberadius-license-panel
```

Restore only while the app is stopped:

```bash
sudo systemctl stop hoberadius-license-panel
cp /var/backups/hoberadius-license-panel/license_panel-YYYYmmdd-HHMMSS.sqlite3 \
  /opt/hoberadius-license-panel/instance/license_panel.sqlite3
sudo systemctl start hoberadius-license-panel
```

## PostgreSQL Backup

PostgreSQL is recommended for commercial production:

```bash
pg_dump --format=custom --file=/var/backups/hoberadius-license-panel/license-panel-$(date +%F).dump "$DATABASE_URL"
```

Restore to a reviewed target database:

```bash
pg_restore --clean --if-exists --dbname "$DATABASE_URL" /var/backups/hoberadius-license-panel/license-panel-YYYY-MM-DD.dump
```

## Deployment Validation Checklist

- App boots under systemd.
- `/api/health` returns JSON `{"ok": true, "status": "healthy"}`.
- Admin login works over HTTPS.
- `/api/license/check` works with a signed request.
- `RATE_LIMITS_ENABLED=1`.
- `SESSION_COOKIE_SECURE=1`.
- `TRUST_PROXY_HEADERS=1` only behind trusted Nginx.
- Nginx forwards `X-Forwarded-For` and `X-Forwarded-Proto`.
- Backups are configured and restore-tested.
- PostgreSQL is planned before real commercial load.
- `LICENSE_CHECK_ALLOW_UNSIGNED=0` in production.
- `LICENSE_CHECK_SIGNATURE_REQUIRED=1` in production.
