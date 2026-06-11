# systemd + env contract — License Panel (no wrapper needed)

## Root cause of the field failure (now fixed in code)

The service crashed with:

```
RuntimeError: Production/bootstrap deployment requires an explicit DATABASE_URL.
```

even though `/etc/hoberadius-license-panel/license-panel.env` contained
`DATABASE_URL`. **`EnvironmentFile=` was working the whole time.** The
bug was the validation itself (`app/__init__.py`): it used **string
equality** — *"explicit"* was defined as *"differs from the built-in
default URI string"*. A correct prod env file points DATABASE_URL at the
canonical path `/opt/hoberadius-license-panel/instance/license_panel.sqlite3`,
which is **exactly the string the default computes on that host** → the
explicit value was misclassified as "default" → boot refused.

The `run_panel.sh` wrapper "fixed" it by accident: it exported the
LEGACY path (`license_panel.db`) which differs as a *string* — passing
the broken check while pointing at the same physical file only because
the owner had made `.db` a symlink.

**Fix (this branch):** "explicit" now means the `DATABASE_URL` env var
EXISTS and is non-empty. The URI's own validity (absolute sqlite path /
postgres) is enforced separately at boot. The wrapper is obsolete.

## Final recommended setup

### `/etc/hoberadius-license-panel/license-panel.env`

```sh
LICENSE_PANEL_ENV=production
FLASK_SECRET=<long-random-48+>
LICENSE_ADMIN_USERNAME=<admin>
LICENSE_ADMIN_PASSWORD=<strong-unique>
# Point at the CANONICAL file. This exact value is now accepted —
# it no longer matters that it equals the built-in default.
DATABASE_URL=sqlite:////opt/hoberadius-license-panel/instance/license_panel.sqlite3
SESSION_COOKIE_SECURE=1
LICENSE_CHECK_SIGNATURE_REQUIRED=1
LICENSE_CHECK_ALLOW_UNSIGNED=0
LICENSE_CHECK_HMAC_SECRET=<long-random-32+>
WHATSAPP_FERNET_KEY=<your-existing-fernet-key>   # DO NOT rotate casually:
                                                  # every encrypted secret
                                                  # (vault, CHR API passwords)
                                                  # is under this key.
```

Notes:
* No `export` keyword — `EnvironmentFile=` format is plain `KEY=value`.
* No quotes needed unless the value contains spaces.
* Point at **`license_panel.sqlite3`**, not the `.db` symlink. The
  symlink may remain for stray tooling, but the service of record uses
  the canonical name.

### `/etc/systemd/system/hoberadius-license-panel.service`

```ini
[Unit]
Description=HobeRadius License Control Panel
After=network.target

[Service]
Type=simple
User=licensepanel
Group=licensepanel
WorkingDirectory=/opt/hoberadius-license-panel
EnvironmentFile=/etc/hoberadius-license-panel/license-panel.env
ExecStart=/opt/hoberadius-license-panel/.venv/bin/gunicorn "wsgi:app" \
    --bind 127.0.0.1:5055 --workers 1 \
    --access-logfile - --error-logfile -
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ReadWritePaths=/opt/hoberadius-license-panel/instance /var/backups/hoberadius-license-panel

[Install]
WantedBy=multi-user.target
```

**Delete `run_panel.sh`** and switch `ExecStart` back to gunicorn
directly (above) after deploying this branch:

```sh
sudo systemctl daemon-reload
sudo systemctl restart hoberadius-license-panel
sudo journalctl -u hoberadius-license-panel -n 30 --no-pager
# expect:  SQLite database resolved to: /opt/.../instance/license_panel.sqlite3
# expect:  NO "Legacy SQLite sibling" warning (the .db symlink is recognised)
```

## Boot-time DB policy (this branch)

| الحالة على القرص | السلوك |
|---|---|
| `license_panel.sqlite3` فقط | إقلاع عادي |
| `.db` symlink → `.sqlite3` | إقلاع عادي، **بدون تحذير** (يتعرّف على الـ symlink) |
| `.db` ملف حقيقي منفصل + الخدمة على الملف الكنسي | **رفض الإقلاع** برسالة split-brain — وحّد أولاً (runbook: docs/DB_PATH_FIX_RUNBOOK.md) |
| DATABASE_URL نسبي (`sqlite:///instance/...`) | رفض الإقلاع (مصيدة الـ cwd التاريخية) |
| DATABASE_URL غائب في production | رفض الإقلاع برسالة تشرح أين يوضع |
