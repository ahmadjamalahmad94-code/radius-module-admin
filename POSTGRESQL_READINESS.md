# PostgreSQL Readiness Notes

This project keeps SQLite as the local/demo default, but commercial production
should use PostgreSQL through SQLAlchemy.

## Production DATABASE_URL

Use a PostgreSQL URL in production:

```env
DATABASE_URL=postgresql+psycopg://license_user:strong-password@127.0.0.1:5432/license_panel
```

The production dependency list includes `psycopg[binary]` so this URL works
after installing `requirements.txt`.

## Current Model Portability

- Models use SQLAlchemy `Integer`, `String`, `Text`, `DateTime`, `Numeric`, and
  `Boolean` types that are portable between SQLite and PostgreSQL.
- Feature and metadata payloads are stored as JSON text. This is intentionally
  simple for v1 and avoids PostgreSQL-only JSON operators.
- License key, plan slug, and admin username uniqueness are enforced at the
  database level.
- Common production query paths now have explicit indexes for dashboard counts,
  license lookup/sorting, check history, renewal history, and audit history.

## Existing SQLite Data

No automatic SQLite-to-PostgreSQL migration is included in this version.

For an existing SQLite install, plan a deliberate migration:

1. Stop the app.
2. Back up the SQLite database file.
3. Provision PostgreSQL and set `DATABASE_URL`.
4. Create tables from the current SQLAlchemy models or a future migration set.
5. Export/import data with a reviewed one-time migration script.
6. Run `python -m pytest -q` and verify `/api/health`, login, and
   `/api/license/check`.

Existing deployed databases will not receive new indexes automatically through
`db.create_all()`. Add the matching indexes through a migration or controlled
DDL before larger production traffic.

## Why Flask-Migrate Is Not Added Yet

The project is still in first production-readiness hardening. Adding a migration
framework is useful once the first real deployment target and database lifecycle
are confirmed. Until then, avoiding a half-configured migration layer is safer
than pretending migrations are complete.
