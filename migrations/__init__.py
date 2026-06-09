"""Fleet schema migrations (panel).

The panel has no pre-existing SQL-migration framework — it creates tables via
SQLAlchemy ``db.create_all()`` and heals existing ones idempotently in
``app.ensure_schema_compatibility``. These numbered modules follow that SAME
idempotent convention (ORM models are the source of truth; each module creates
*its* tables with ``checkfirst=True`` and any views/indexes that ORM metadata
can't express), so they are safe to re-run and apply cleanly on a fresh DB.

Each module exposes ``upgrade()`` and ``downgrade()`` and must be called inside a
Flask app context (so ``db.engine`` is bound). Filenames are numbered to encode
apply order (001 before 002, …); load them by path (the digit prefix is not a
valid Python identifier) — see tests/test_fleet_models_p2a.py for the loader.
"""
