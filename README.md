# HobeRadius License Control Panel

Central vendor/admin licensing panel for selling and managing RADIUS subscriptions.

This is not the customer RADIUS app. It is a standalone control panel that issues and checks licenses. Customer RADIUS installations call `POST /api/license/check` periodically and enforce the returned mode locally.

## Local Setup

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

## Development Admin

Default local credentials:

```text
username: admin
password: admin12345
```

Change these before any real deployment using:

```text
LICENSE_ADMIN_USERNAME
LICENSE_ADMIN_PASSWORD
LICENSE_ADMIN_EMAIL
FLASK_SECRET
```

See `.env.example`.

## Implemented Routes

Admin:

- `GET /login`
- `POST /login`
- `POST /logout`
- `GET /admin`
- `GET /admin/dashboard`
- `GET/POST /admin/customers/new`
- `GET /admin/customers`
- `GET /admin/customers/<id>`
- `GET/POST /admin/customers/<id>/edit`
- `GET/POST /admin/plans/new`
- `GET /admin/plans`
- `GET/POST /admin/plans/<id>/edit`
- `GET/POST /admin/licenses/new`
- `GET /admin/licenses`
- `GET /admin/licenses/<id>`
- `POST /admin/licenses/<id>/renew`
- `POST /admin/licenses/<id>/suspend`
- `POST /admin/licenses/<id>/activate`
- `POST /admin/licenses/<id>/revoke`
- `POST /admin/licenses/<id>/reset-fingerprints`
- `GET /admin/checks`
- `GET /admin/renewals`
- `GET /admin/audit-logs`
- `GET/POST /admin/settings`

API:

- `GET /api/health`
- `POST /api/license/check`

## License Check API

Request:

```python
import requests

payload = {
    "license_key": "HBR-2026-ABCD-EFGH-9K22",
    "server_fingerprint": "abc123",
    "hostname": "client-vps-1",
    "version": "1.0.0",
    "install_id": "optional-install-id",
    "domain": "radius.example.com",
}

res = requests.post("https://license.example.com/api/license/check", json=payload, timeout=10)
data = res.json()
```

Expected local enforcement by the customer RADIUS installation:

- `mode=active`: all operations allowed.
- `mode=limited`: allow admin login and read-only views; block new users/cards/sync actions.
- `mode=denied`: block sensitive operations and show contact support.

## Data Models

- `Admin`
- `Customer`
- `Plan`
- `License`
- `LicenseCheck`
- `Renewal`
- `AuditLog`
- `Setting`

## Verification

```powershell
python -m compileall app
python -m pytest -q
```

## Database For Production

SQLite remains the default for local demos and small single-process testing.
Commercial production should use PostgreSQL:

```env
DATABASE_URL=postgresql+psycopg://license_user:strong-password@127.0.0.1:5432/license_panel
```

See `POSTGRESQL_READINESS.md` before moving existing SQLite data to PostgreSQL.

## First Admin Bootstrap

For a fresh database, the first admin is created from:

```text
LICENSE_ADMIN_USERNAME
LICENSE_ADMIN_PASSWORD
LICENSE_ADMIN_EMAIL
```

Explicit setup command:

```powershell
flask --app wsgi init-db
```

`init-db` creates tables, sample plans/settings, and the first admin from the
environment when no admin exists. Use `bootstrap-admin` only for an existing
database that has tables but no admin account yet. It refuses to run if an admin
already exists and never prints the admin password.

## Arabic Summary

هذا المشروع لوحة مركزية لإدارة تراخيص واشتراكات منتج RADIUS. لا يحتوي على نظام RADIUS نفسه، ولا يستورد من مشروع العميل. وظيفته إصدار التراخيص وفحص حالتها وإدارة التجديدات والبصمات والسجلات.
