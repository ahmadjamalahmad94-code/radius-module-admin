"""بيئة Alembic — تربط الهجرات بميتاداتا التطبيق الفعلية.

target_metadata يُبنى من create_app(TestingConfig-like) بدون تشغيل الخوادم:
نستورد الموديلات فقط (app.models + fleet models عبر تسجيل الـ blueprints يحدث
داخل create_app؛ هنا نكتفي باستيراد الموديولات الحاملة للموديلات مباشرة كي
لا نشغّل منطق الإقلاع).

رابط القاعدة: DATABASE_URL إن وُجد، وإلا مسار SQLite القياسي من app.db_path.
"""
from __future__ import annotations

import os
import sys
from logging.config import fileConfig

from alembic import context
from sqlalchemy import create_engine, pool

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)


def _database_url() -> str:
    url = (os.environ.get("DATABASE_URL") or "").strip()
    if url:
        return url
    from app.db_path import canonical_database_uri  # noqa: PLC0415
    return canonical_database_uri()


def _target_metadata():
    # استيراد الموديلات يسجّلها على db.metadata — بلا create_app كامل.
    from app.extensions import db  # noqa: PLC0415
    import app.models  # noqa: F401, PLC0415
    import app.notifications.models  # noqa: F401, PLC0415
    for mod in (
        "fleet.registry.models_chr",
        "fleet.registry.secrets_vault",
        "fleet.health.models_health",
        "fleet.brain.models_session",
        "fleet.notify.models_alert",
        "fleet.dns.models_dns",
        "fleet.sync.models",
    ):
        try:
            __import__(mod)
        except Exception:  # noqa: BLE001 — موديول اختياري/أُعيدت تسميته
            pass
    return db.metadata


def run_migrations_offline() -> None:
    context.configure(
        url=_database_url(),
        target_metadata=_target_metadata(),
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_as_batch=True,  # SQLite: ALTER عبر batch mode
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    engine = create_engine(_database_url(), poolclass=pool.NullPool)
    with engine.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=_target_metadata(),
            render_as_batch=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
