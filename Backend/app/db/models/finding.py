from __future__ import annotations

from datetime import datetime
from typing import Any

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, enum_column, utcnow
from app.db.enums import (
    FindingCategory,
    FindingSource,
    Severity,
    VerificationStatus,
)


class Finding(TimestampMixin, Base):
    __tablename__ = "findings"
    __table_args__ = (
        sa.UniqueConstraint("assessment_id", "fingerprint", name="uq_finding_fingerprint"),
        sa.Index("ix_findings_assessment_severity", "assessment_id", "final_severity"),
        sa.Index("ix_findings_assessment_status", "assessment_id", "verification_status"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    assessment_id: Mapped[int] = mapped_column(
        sa.ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False, index=True
    )
    scan_id: Mapped[int | None] = mapped_column(
        sa.ForeignKey("scans.id", ondelete="SET NULL"), nullable=True, index=True
    )
    source: Mapped[FindingSource] = mapped_column(enum_column(FindingSource), nullable=False)
    fingerprint: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    title: Mapped[str] = mapped_column(sa.String(500), nullable=False)
    description: Mapped[str | None] = mapped_column(sa.Text)
    category: Mapped[FindingCategory] = mapped_column(
        enum_column(FindingCategory),
        nullable=False,
        default=FindingCategory.UNCATEGORIZED,
    )
    owasp_category: Mapped[str | None] = mapped_column(sa.String(100))
    cwe: Mapped[str | None] = mapped_column(sa.String(50))
    affected_url: Mapped[str | None] = mapped_column(sa.String(2048))
    http_method: Mapped[str | None] = mapped_column(sa.String(20))
    parameter: Mapped[str | None] = mapped_column(sa.String(200))
    tool_severity: Mapped[Severity | None] = mapped_column(enum_column(Severity))
    ai_suggested_severity: Mapped[Severity | None] = mapped_column(enum_column(Severity))
    final_severity: Mapped[Severity | None] = mapped_column(enum_column(Severity))
    tool_confidence: Mapped[str | None] = mapped_column(sa.String(50))
    verification_status: Mapped[VerificationStatus] = mapped_column(
        enum_column(VerificationStatus),
        nullable=False,
        default=VerificationStatus.PENDING,
        index=True,
    )
    rejection_reason: Mapped[str | None] = mapped_column(sa.Text)
    verified_by: Mapped[int | None] = mapped_column(
        sa.ForeignKey("users.id", ondelete="SET NULL")
    )
    verified_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    final_remediation: Mapped[str | None] = mapped_column(sa.Text)
    first_seen_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, default=utcnow
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, default=utcnow
    )
    seen_count: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=1)
    raw: Mapped[dict[str, Any]] = mapped_column(sa.JSON, nullable=False, default=dict)

    evidence: Mapped[list["Evidence"]] = relationship(  # noqa: F821, UP037
        back_populates="finding", cascade="all, delete-orphan"
    )
    ai_analyses: Mapped[list["AIAnalysis"]] = relationship(  # noqa: F821, UP037
        back_populates="finding", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"Finding(id={self.id!r}, title={self.title!r})"
