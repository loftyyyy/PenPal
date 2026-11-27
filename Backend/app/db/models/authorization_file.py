from __future__ import annotations

from datetime import datetime

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin


class AuthorizationFile(TimestampMixin, Base):
    """A target-ownership token the assessor publishes at a well-known path."""

    __tablename__ = "authorization_files"
    __table_args__ = (
        sa.UniqueConstraint("token", name="uq_authorization_file_token"),
        sa.Index(
            "ix_authorization_files_assessment_target",
            "assessment_id",
            "target",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    assessment_id: Mapped[int] = mapped_column(
        sa.ForeignKey("assessments.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    created_by: Mapped[int | None] = mapped_column(
        sa.ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    target: Mapped[str] = mapped_column(sa.String(2048), nullable=False)
    token: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    verification_path: Mapped[str] = mapped_column(
        sa.String(255), nullable=False, default="/.well-known/penpal-verification.txt"
    )
    expires_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False
    )
    revoked_at: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True), nullable=True
    )
    verified_at: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True), nullable=True
    )
    last_checked_at: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True), nullable=True
    )
    failure_reason: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
