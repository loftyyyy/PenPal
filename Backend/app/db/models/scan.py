from __future__ import annotations

from datetime import datetime
from typing import Any

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, enum_column
from app.db.enums import ScanStatus, ScanTool


class Scan(TimestampMixin, Base):
    __tablename__ = "scans"
    __table_args__ = (sa.Index("ix_scans_assessment_status", "assessment_id", "status"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    assessment_id: Mapped[int] = mapped_column(
        sa.ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False, index=True
    )
    tool: Mapped[ScanTool] = mapped_column(enum_column(ScanTool), nullable=False)
    profile: Mapped[str] = mapped_column(sa.String(50), nullable=False)
    target: Mapped[str] = mapped_column(sa.String(2048), nullable=False)
    status: Mapped[ScanStatus] = mapped_column(
        enum_column(ScanStatus), nullable=False, default=ScanStatus.QUEUED, index=True
    )
    progress: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=0)
    started_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    error: Mapped[str | None] = mapped_column(sa.Text)
    raw_output_path: Mapped[str | None] = mapped_column(sa.String(1024))
    raw_output_sha256: Mapped[str | None] = mapped_column(sa.String(64))
    tool_version: Mapped[str | None] = mapped_column(sa.String(200))
    parameters: Mapped[dict[str, Any]] = mapped_column(sa.JSON, nullable=False, default=dict)
    created_by: Mapped[int] = mapped_column(
        sa.ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"Scan(id={self.id!r}, tool={self.tool!r}, status={self.status!r})"
