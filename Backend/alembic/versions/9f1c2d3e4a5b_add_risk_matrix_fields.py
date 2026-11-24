"""add likelihood and impact to findings

Revision ID: 9f1c2d3e4a5b
Revises: 0c3a6868812f
Create Date: 2026-11-24
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "9f1c2d3e4a5b"
down_revision = "0c3a6868812f"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("findings", sa.Column("likelihood", sa.Integer(), nullable=True))
    op.add_column("findings", sa.Column("impact", sa.Integer(), nullable=True))


def downgrade() -> None:
    op.drop_column("findings", "impact")
    op.drop_column("findings", "likelihood")
