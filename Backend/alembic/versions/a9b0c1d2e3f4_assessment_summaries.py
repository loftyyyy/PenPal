"""add assessment summary workflow table

Revision ID: a9b0c1d2e3f4
Revises: e7f8a9b0c1d2
Create Date: 2026-11-24
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "a9b0c1d2e3f4"
down_revision = "e7f8a9b0c1d2"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "assessment_summaries",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "assessment_id",
            sa.Integer(),
            sa.ForeignKey("assessments.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column(
            "generated_by",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("provider", sa.String(length=50), nullable=False),
        sa.Column("model", sa.String(length=200), nullable=False),
        sa.Column("sanitized_input", sa.Text(), nullable=False),
        sa.Column("output", sa.JSON(), nullable=True),
        sa.Column("edited_text", sa.Text(), nullable=True),
        sa.Column("overall_risk", sa.String(length=32), nullable=True),
        sa.Column(
            "ai_analysis_id",
            sa.Integer(),
            sa.ForeignKey("ai_analyses.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "approved_by",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_assessment_summaries_assessment_id",
        "assessment_summaries",
        ["assessment_id"],
    )
    op.create_index(
        "ix_assessment_summaries_status",
        "assessment_summaries",
        ["status"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_assessment_summaries_status", table_name="assessment_summaries"
    )
    op.drop_index(
        "ix_assessment_summaries_assessment_id",
        table_name="assessment_summaries",
    )
    op.drop_table("assessment_summaries")
