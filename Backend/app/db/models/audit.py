from __future__ import annotations

from typing import Any

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin


class AuditLog(TimestampMixin, Base):
    """Append-only log. No API may update or delete rows."""

    __tablename__ = "audit_log"
    __table_args__ = (sa.Index("ix_audit_assessment_created", "assessment_id", "created_at"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    assessment_id: Mapped[int | None] = mapped_column(
        sa.ForeignKey("assessments.id", ondelete="SET NULL"), nullable=True, index=True
    )
    user_id: Mapped[int | None] = mapped_column(
        sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    action: Mapped[str] = mapped_column(sa.String(100), nullable=False, index=True)
    entity_type: Mapped[str | None] = mapped_column(sa.String(50))
    entity_id: Mapped[str | None] = mapped_column(sa.String(100))
    details: Mapped[dict[str, Any]] = mapped_column(sa.JSON, nullable=False, default=dict)

    def __repr__(self) -> str:  # pragma: no cover
        return f"AuditLog(id={self.id!r}, action={self.action!r})"
