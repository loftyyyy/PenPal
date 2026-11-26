"""add target authorization files

Revision ID: f4a5b6c7d8e9
Revises: b1c2d3e4f5a6
Create Date: 2026-11-27
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "f4a5b6c7d8e9"
down_revision = "b1c2d3e4f5a6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "authorization_files",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "assessment_id",
            sa.Integer(),
            sa.ForeignKey("assessments.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "created_by",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("target", sa.String(length=2048), nullable=False),
        sa.Column("token", sa.String(length=128), nullable=False),
        sa.Column(
            "verification_path",
            sa.String(length=255),
            nullable=False,
            server_default="/.well-known/penpal-verification.txt",
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_checked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("failure_reason", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("token", name="uq_authorization_file_token"),
    )
    op.create_index(
        "ix_authorization_files_assessment_id",
        "authorization_files",
        ["assessment_id"],
    )
    op.create_index(
        "ix_authorization_files_created_by",
        "authorization_files",
        ["created_by"],
    )
    op.create_index(
        "ix_authorization_files_assessment_target",
        "authorization_files",
        ["assessment_id", "target"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_authorization_files_assessment_target",
        table_name="authorization_files",
    )
    op.drop_index(
        "ix_authorization_files_created_by", table_name="authorization_files"
    )
    op.drop_index(
        "ix_authorization_files_assessment_id", table_name="authorization_files"
    )
    op.drop_table("authorization_files")
