# Owner runbook — reconcile `license_panel.db` vs `license_panel.sqlite3`

**Audience:** the panel's owner / operator with SSH on the prod host. You run
every command yourself; the Claude session that produced this fix has NO
access to your server.

**Goal:** end up with EXACTLY ONE SQLite file (`license_panel.sqlite3`), no
data loss, no surprises. The code change in this branch hardens the panel so
this drift cannot happen again — but the existing two files on disk are a
*data* problem that only you can resolve safely.

> **DO NOT** delete either file before you finish the inspection steps below.
> Either file may hold rows that aren't in the other.

---

## 0. What the code fix does (already in this branch)

- `app/db_path.py` is now the single source of truth for the SQLite path. It
  is absolute, anchored at the app package, and **independent of the working
  directory** of whatever process launches the panel.
- `app/__init__.py` calls `validate_database_uri()` at boot and **refuses to
  start** if `DATABASE_URL` is a relative `sqlite:///` URI (the original
  trigger). It also logs the resolved on-disk path on every boot and warns if
  a `license_panel.db` sibling is detected.

So once you deploy this branch, the panel will keep reading the canonical
`license_panel.sqlite3` and will SHOUT in the logs about the legacy `.db`
sibling until you remove it.

---

## 1. Stop the panel cleanly

```sh
sudo systemctl stop hoberadius-license-panel
# Confirm no python is still holding either file open:
sudo lsof +D /opt/hoberadius-license-panel/instance || true
```

If `lsof` lists ANY process holding the files, stop those too (whatsapp-drain
timer, vpn-quota-sync timer, etc.) before continuing.

---

## 2. Inventory both files

```sh
cd /opt/hoberadius-license-panel/instance
ls -la license_panel.db license_panel.sqlite3 2>/dev/null
```

You should see both files with their sizes + mtimes. Note them down.

```sh
# Row counts for the critical tables in EACH file.
for f in license_panel.sqlite3 license_panel.db; do
  [ -f "$f" ] || continue
  echo "=== $f ==="
  for t in admins customers licenses plans settings audit_logs \
           customer_users license_payment_requests; do
    n=$(sqlite3 "$f" "SELECT COUNT(*) FROM $t;" 2>/dev/null || echo "(missing)")
    echo "  $t: $n"
  done
done
```

```sh
# Latest activity timestamps in each file:
for f in license_panel.sqlite3 license_panel.db; do
  [ -f "$f" ] || continue
  echo "=== $f ==="
  sqlite3 "$f" "SELECT 'audit_logs', MAX(created_at) FROM audit_logs;
                SELECT 'settings',    MAX(updated_at) FROM settings;
                SELECT 'customers',   MAX(updated_at) FROM customers;
                SELECT 'admins',      MAX(updated_at) FROM admins;" 2>/dev/null
done
```

Write down the totals + max timestamps for both files. **DO NOT DELETE EITHER
FILE YET.**

---

## 3. Decide which file is authoritative

The code base (and your live `systemd` service) read `license_panel.sqlite3`
— this is the file that grew with real production traffic. The `.db` file is
the legacy sibling that some scripts / shell sessions accidentally wrote to.

In **most cases**, after step 2 you should see:

- `license_panel.sqlite3` has the HIGHER row counts in `audit_logs`,
  `customers`, `license_payment_requests` (anything customer-driven).
- `license_panel.db` may have HIGHER `settings.updated_at` or extra rows in
  `settings` (e.g. the PANEL_WG private key the field report described) —
  those were the manual edits that "went to the wrong file".

If that matches what you see, **canonical = `license_panel.sqlite3`** and you
will MERGE selected rows from `.db` into `.sqlite3`. Go to step 5.

If the picture is reversed (e.g. `.db` has more customer activity than
`.sqlite3`), **STOP**. That means the running service was actually using
`.db` for some period — Claude's automatic answer is wrong for your case.
Take both backups (step 4) and report back before doing anything else.

---

## 4. Back up BOTH files (mandatory, before any change)

```sh
sudo install -d -m 0750 -o licensepanel -g licensepanel /var/backups/hoberadius-license-panel
STAMP=$(date -u +%Y%m%d-%H%M%S)
sudo -u licensepanel sqlite3 /opt/hoberadius-license-panel/instance/license_panel.sqlite3 \
    ".backup '/var/backups/hoberadius-license-panel/license_panel.sqlite3.$STAMP.bak'"
sudo -u licensepanel sqlite3 /opt/hoberadius-license-panel/instance/license_panel.db \
    ".backup '/var/backups/hoberadius-license-panel/license_panel.db.$STAMP.bak'"
ls -la /var/backups/hoberadius-license-panel/
```

`sqlite3 .backup` is the safe path — it produces a consistent snapshot even
if WAL mode is enabled. Do NOT use plain `cp`.

---

## 5. Pull the missing rows from `.db` → `.sqlite3`

`sqlite3` supports `ATTACH` so you can read both files from one session. Be
deliberate: only merge what was actually unique to `.db`. The `settings`
table is the most common case (manual edits like the panel's WG key).

```sh
sudo -u licensepanel sqlite3 /opt/hoberadius-license-panel/instance/license_panel.sqlite3 <<'SQL'
ATTACH DATABASE '/opt/hoberadius-license-panel/instance/license_panel.db' AS legacy;

-- 1. INSPECT FIRST. List settings keys that exist only in legacy:
SELECT 'legacy_only:', l.key, l.value
  FROM legacy.settings l
  LEFT JOIN main.settings m ON m.key = l.key
 WHERE m.key IS NULL;

-- 2. List settings keys that exist in BOTH but with different values:
SELECT 'differs:', l.key, l.value AS legacy_value, m.value AS main_value
  FROM legacy.settings l
  JOIN main.settings m ON m.key = l.key
 WHERE m.value != l.value;
SQL
```

Read the output carefully. For each row you want to bring over, run a
**targeted** `INSERT OR REPLACE` — never a blanket copy:

```sh
sudo -u licensepanel sqlite3 /opt/hoberadius-license-panel/instance/license_panel.sqlite3 <<'SQL'
ATTACH DATABASE '/opt/hoberadius-license-panel/instance/license_panel.db' AS legacy;

-- Example: pull the panel's WireGuard private key (and ONLY that key)
-- from legacy → main. Replace 'panel_wg.privkey' with your actual key name.
INSERT OR REPLACE INTO main.settings (key, value, updated_at)
  SELECT key, value, updated_at
    FROM legacy.settings
   WHERE key = 'panel_wg.privkey';

-- Verify it landed:
SELECT key, substr(value, 1, 12) || '...' FROM main.settings WHERE key = 'panel_wg.privkey';
SQL
```

If `customers` / `customer_users` / `admins` rows exist only in legacy,
copy them ONE AT A TIME with explicit IDs to avoid clobbering primary-key
sequences:

```sql
-- Walk through legacy.customers row-by-row, decide for each one whether
-- you actually want it in the canonical DB.  Example merge if (and only
-- if) the row is genuinely missing:
INSERT INTO main.customers (id, company_name, contact_name, email, phone, ...)
  SELECT id, company_name, contact_name, email, phone, ...
    FROM legacy.customers
   WHERE id = 42;
```

**If you're unsure about any row, DON'T copy it.** Re-create the data through
the panel UI instead — that's safer than blind SQL.

---

## 6. Move the legacy file out of the way

Once you've merged what you need:

```sh
sudo mv /opt/hoberadius-license-panel/instance/license_panel.db \
        /opt/hoberadius-license-panel/instance/license_panel.db.RECONCILED-$STAMP
sudo chown licensepanel:licensepanel \
        /opt/hoberadius-license-panel/instance/license_panel.db.RECONCILED-$STAMP
```

Move, do **not** delete — keep the renamed file around for a week or two in
case you discover a missed row. Then archive it to your usual backup target.

---

## 7. Sanity-check the env + start the service

```sh
# Confirm DATABASE_URL is either absent (use the canonical default) or an
# absolute path. The code change rejects relative sqlite:/// URIs at boot.
sudo grep DATABASE_URL /etc/hoberadius-license-panel/license-panel.env || \
  echo "(no DATABASE_URL set — using canonical default, which is correct)"

sudo systemctl start hoberadius-license-panel
sudo journalctl -u hoberadius-license-panel -n 50 --no-pager
```

Look for these two log lines on boot (added by this branch):

```
SQLite database resolved to: /opt/hoberadius-license-panel/instance/license_panel.sqlite3
```

There should be NO `Legacy SQLite sibling detected ...` warning once
`license_panel.db` has been renamed.

Open the panel in a browser and confirm:

- the admin login still works,
- the dashboard counts match what was there before,
- the formerly-missing panel WG key (or whatever setting tipped you off) now
  resolves correctly.

---

## 8. If anything is missing after step 7

You still have:

- `/var/backups/hoberadius-license-panel/license_panel.sqlite3.<STAMP>.bak`
- `/var/backups/hoberadius-license-panel/license_panel.db.<STAMP>.bak`
- The renamed `license_panel.db.RECONCILED-<STAMP>` next to the live DB

Stop the service, restore from a backup, and contact me before re-trying the
merge. Nothing is destroyed; the panel can fall back to either backup with a
single `cp`.
