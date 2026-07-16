"""baseline - existing schema (no-op)

Revision ID: 1b12d2e96730
Revises: 
Create Date: 2026-07-16 18:43:32.843194
"""
from alembic import op
import sqlalchemy as sa


revision = '1b12d2e96730'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
