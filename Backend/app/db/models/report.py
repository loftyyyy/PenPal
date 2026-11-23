from __future__ import annotations

from typing import Any

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, enum_column
from app.db.enums import ReportFormat, ReportStatus


class Report(TimestampMixin, Base):
    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(primary_key=True)
    assessment_id: Mapped[int] = mapped_column(
        sa.ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False, index=True
    )
    format: Mapped[ReportFormat] = mapped_column(enum_column(ReportFormat), nullable=False)
    status: Mapped[ReportStatus] = mapped_column(
        enum_column(ReportStatus), nullable=False, default=ReportStatus.PENDING
    )
    file_path: Mapped[str | None] = mapped_column(sa.String(1024))
    sha256: Mapped[str | None] = mapped_column(sa.String(64))
    generated_by: Mapped[int] = mapped_column(
        sa.ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    summary_counts: Mapped[dict[str, Any]] = mapped_column(
        sa.JSON, nullable=False, default=dict
    )
    error: Mapped[str | None] = mapped_column(sa.Text)

    def __repr__(self) -> str:  # pragma: no cover
        return f"Report(id={self.id!r}, format={self.format!r}, status={self.status!r})"
