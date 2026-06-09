"""
Migration: add missing columns to customer_backup_artifacts
Run from the radius-module-admin directory:
    python migrate_backup_artifacts.py
"""
import sqlite3
import os
import sys

DB_PATH = os.path.join(os.path.dirname(__file__), "instance", "license_panel.sqlite3")

if not os.path.exists(DB_PATH):
    print(f"ERROR: DB not found at {DB_PATH}")
    sys.exit(1)

# Columns defined in the model but missing from the old table schema.
# Each tuple: (column_name, sql_type, default_value_literal)
EXPECTED = [
    ("backup_reference",  "VARCHAR(160)", "''"),
    ("module",            "VARCHAR(60)",  "'radius-module'"),
    ("instance_id",       "VARCHAR(120)", "''"),
    ("kind",              "VARCHAR(40)",  "'sqlite'"),
    ("size",              "INTEGER",      "0"),
    ("upload_mode",       "VARCHAR(40)",  "'metadata_only'"),
    ("content_included",  "BOOLEAN",      "0"),
    ("stored_filename",   "VARCHAR(255)", "''"),
    ("result_status",     "VARCHAR(40)",  "'received'"),
    ("remote_created_at", "VARCHAR(40)",  "''"),
    ("received_at",       "DATETIME",     "'1970-01-01 00:00:00'"),
]

conn = sqlite3.connect(DB_PATH)
conn.execute("PRAGMA journal_mode=WAL")

existing = {r[1] for r in conn.execute("PRAGMA table_info(customer_backup_artifacts)").fetchall()}
print(f"Existing columns ({len(existing)}): {sorted(existing)}\n")

added = []
for col, col_type, default in EXPECTED:
    if col in existing:
        print(f"  SKIP  {col} (already exists)")
    else:
        sql = (
            f"ALTER TABLE customer_backup_artifacts "
            f"ADD COLUMN {col} {col_type} NOT NULL DEFAULT {default}"
        )
        print(f"  ADD   {col}")
        conn.execute(sql)
        added.append(col)

conn.commit()
conn.close()

print(f"\nDone — added {len(added)} column(s): {added or 'none'}")
