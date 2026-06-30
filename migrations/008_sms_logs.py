"""Migration 008 — sms_logs.

Audit table for OWNER→customer SMS sends via TweetSMS (who/when/to/status). The
provider credentials live encrypted in the ``settings`` table (``tweetsms.*``)
and are NEVER stored here — only the destination + outcome.

Idempotent: ``create_all(..., checkfirst=True)`` is a no-op when the table
already exists (fresh ``db.create_all()`` boots also build it).
"""
from __future__ import annotations

from app.extensions import db
from app.models import SmsLog

_TABLES = [SmsLog.__table__]


def upgrade() -> None:
    db.metadata.create_all(bind=db.engine, tables=_TABLES, checkfirst=True)


def downgrade() -> None:
    db.metadata.drop_all(bind=db.engine, tables=_TABLES, checkfirst=True)
