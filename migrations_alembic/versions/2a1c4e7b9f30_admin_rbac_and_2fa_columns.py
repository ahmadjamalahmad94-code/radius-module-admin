"""admin RBAC role_key + 2FA (totp) columns

Revision ID: 2a1c4e7b9f30
Revises: 1b12d2e96730
Create Date: 2026-07-16
"""
from alembic import op
import sqlalchemy as sa

revision = "2a1c4e7b9f30"
down_revision = "1b12d2e96730"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("admins") as batch:
        batch.add_column(sa.Column("role_key", sa.String(length=20),
                                   nullable=False, server_default="operator"))
        batch.add_column(sa.Column("totp_secret", sa.String(length=64),
                                   nullable=False, server_default=""))
        batch.add_column(sa.Column("totp_enabled", sa.Boolean(),
                                   nullable=False, server_default=sa.false()))
    # مواءمة رجعية: كل super موجود = role_key super_admin
    op.execute("UPDATE admins SET role_key='super_admin' WHERE is_super_admin=1")


def downgrade() -> None:
    with op.batch_alter_table("admins") as batch:
        batch.drop_column("totp_enabled")
        batch.drop_column("totp_secret")
        batch.drop_column("role_key")
