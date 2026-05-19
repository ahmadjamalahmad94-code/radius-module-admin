# Deployment Checklist

This checklist is for the standalone HobeRadius License Control Panel only.
It is the vendor/admin licensing panel, not the customer RADIUS application.

## Required Environment Variables

Set these before any real deployment:

- `LICENSE_PANEL_ENV=production`
- `FLASK_SECRET`
- `DATABASE_URL`
- `LICENSE_ADMIN_USERNAME`
- `LICENSE_ADMIN_PASSWORD`
- `LICENSE_ADMIN_EMAIL`
- `DEFAULT_GRACE_DAYS`
- `DEFAULT_CURRENCY`
- `SUPPORT_EMAIL`
- `SUPPORT_PHONE`
- `AUTO_INIT_DB`
- `RATE_LIMITS_ENABLED`
- `LOGIN_RATE_LIMIT_MAX`
- `LOGIN_RATE_LIMIT_WINDOW_SECONDS`
- `LICENSE_CHECK_RATE_LIMIT_MAX`
- `LICENSE_CHECK_RATE_LIMIT_WINDOW_SECONDS`
- `LICENSE_KEY_RATE_LIMIT_MAX`
- `LICENSE_KEY_RATE_LIMIT_WINDOW_SECONDS`
- `TRUST_PROXY_HEADERS`
- `SESSION_COOKIE_SECURE`
- `SESSION_COOKIE_SAMESITE`
- `SESSION_LIFETIME_SECONDS`
- `LOG_LEVEL`

## Forbidden Defaults

Never run production with these values:

- `FLASK_SECRET=dev-secret-change-me`
- `FLASK_SECRET=change-this-secret`
- `LICENSE_ADMIN_PASSWORD=admin12345`
- `LICENSE_ADMIN_PASSWORD=change-this-password`
- `LICENSE_PANEL_ENV=local`
- `SESSION_COOKIE_SECURE=0`
- `RATE_LIMITS_ENABLED=0`

The application now refuses to start in `production` if the built-in default
secret or default admin password is still active.

## Local Demo Steps

Use local demo only on a trusted machine:

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

Local demo credentials are allowed only for development:

```text
username: admin
password: admin12345
```

## Nginx And TLS Notes

- Put the Flask app behind Nginx or another reverse proxy.
- Use HTTPS only in production.
- Redirect HTTP to HTTPS.
- Enable modern TLS certificates with automatic renewal, for example Certbot.
- Forward the original client IP with `X-Forwarded-For`.
- Set `TRUST_PROXY_HEADERS=1` only when the Flask app is reachable only from
  that trusted reverse proxy.
- Keep `SESSION_COOKIE_SECURE=1` in production.
- Keep admin routes private where possible, for example with firewall rules,
  VPN, or IP allowlists.
- Do not expose the development server directly to the internet.

Example proxy shape:

```nginx
server {
    listen 443 ssl http2;
    server_name license.example.com;

    ssl_certificate /etc/letsencrypt/live/license.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/license.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:5055;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## Gunicorn Readiness

Production should use the WSGI entrypoint:

```bash
python -m pip install gunicorn
gunicorn "wsgi:app" --bind 127.0.0.1:5055 --workers 2
```

Do not use `python run.py` as the production service command. `run.py` is for
local development.

## Database Notes

SQLite is acceptable for:

- local demo
- early internal testing
- a very small single-process deployment

PostgreSQL is recommended before real commercial production because it provides:

- safer concurrent writes
- stronger backup tooling
- better operational visibility
- easier future scaling

If using SQLite temporarily in production:

- keep the database outside the Git working tree
- back it up frequently
- run only one app process unless the write behavior has been tested carefully
- avoid network filesystems for the SQLite database file

## Backup Notes

Back up all persistent data:

- database file or PostgreSQL database
- environment variables/secrets in the server secret manager
- Nginx virtual host config
- deployment service files
- application version or Git commit hash

Recommended schedule:

- daily automated database backup
- weekly off-server backup verification
- test restore before relying on the backup process

For PostgreSQL, prefer:

```bash
pg_dump --format=custom --file=license-panel-$(date +%F).dump "$DATABASE_URL"
```

For SQLite, stop writes or take an online-safe backup before copying the file.

## Rate Limit Note

The current rate limiter is in-memory and suitable for a first single-process
deployment. It is not enough for multiple workers or multiple servers.

TODO before multi-worker production:

- move rate limit counters to Redis or another shared store
- rate-limit by IP plus license key for `/api/license/check`
- add separate stricter limits for failed admin login attempts

## Customer RADIUS License Check

Customer RADIUS installations should periodically call:

```text
POST https://license.example.com/api/license/check
```

Example request:

```json
{
  "license_key": "HBR-2026-ABCD-EFGH-9K22",
  "server_fingerprint": "server-fingerprint-hash",
  "hostname": "client-vps-1",
  "version": "1.0.0",
  "install_id": "optional-install-id",
  "domain": "radius.customer.example"
}
```

Expected response modes:

- `mode=active`: allow normal operations.
- `mode=limited`: allow admin login and read-only views; block new users,
  cards, sync, and sensitive server actions.
- `mode=denied`: block sensitive operations and show a support message.

The customer RADIUS installation must enforce these modes locally. The license
panel only returns the decision.

## Production Safety Checklist

Before going live:

- Confirm this project is deployed alone and does not import from
  `radius-module` or `radius-module-app`.
- Set `LICENSE_PANEL_ENV=production`.
- Set a long random `FLASK_SECRET`.
- Set a strong non-default `LICENSE_ADMIN_PASSWORD`.
- Store secrets outside Git.
- Confirm `.env` is not committed.
- Use HTTPS with valid certificates.
- Put the app behind Nginx or a production WSGI server.
- Verify `/api/health` works over HTTPS.
- Verify `/login` is HTTPS-only.
- Verify `/api/license/check` does not expose private customer data.
- Confirm backups are automated and restore-tested.
- Decide whether SQLite is still acceptable or migrate to PostgreSQL.
- Review firewall access to the admin panel.
- Confirm rate limits are enabled.
- Plan Redis-backed rate limits before using multiple workers.
- Run verification commands after deployment.

## Verification Commands

Run before deployment and after deployment updates:

```powershell
python -m compileall app
python -m pytest -q
```

Also check repository state before packaging or pushing:

```powershell
git status --short
```
