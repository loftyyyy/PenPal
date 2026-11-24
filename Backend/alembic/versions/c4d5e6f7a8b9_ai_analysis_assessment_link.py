"""link AI analyses to assessments for summary rows

Revision ID: c4d5e6f7a8b9
Revises: 9f1c2d3e4a5b
Create Date: 2026-11-24
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "c4d5e6f7a8b9"
down_revision = "9f1c2d3e4a5b"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("ai_analyses") as batch:
        batch.alter_column(
            "finding_id", existing_type=sa.Integer(), nullable=True
        )
        batch.add_column(sa.Column("assessment_id", sa.Integer(), nullable=True))
        batch.create_index("ix_ai_analyses_assessment_id", ["assessment_id"])
        batch.create_foreign_key(
            "fk_ai_analyses_assessment_id_assessments",
            "assessments",
            ["assessment_id"],
            ["id"],
            ondelete="CASCADE",
        )


def downgrade() -> None:
    with op.batch_alter_table("ai_analyses") as batch:
        batch.drop_constraint(
            "fk_ai_analyses_assessment_id_assessments", type_="foreignkey"
        )
        batch.drop_index("ix_ai_analyses_assessment_id")
        batch.drop_column("assessment_id")
        batch.alter_column(
            "finding_id", existing_type=sa.Integer(), nullable=False
        )
