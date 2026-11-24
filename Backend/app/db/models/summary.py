from __future__ import annotations

from datetime import datetime
from typing import Any

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, enum_column
from app.db.enums import Severity, SummaryStatus


class AssessmentSummary(TimestampMixin, Base):
    __tablename__ = "assessment_summaries"

    id: Mapped[int] = mapped_column(primary_key=True)
    assessment_id: Mapped[int] = mapped_column(
        sa.ForeignKey("assessments.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    status: Mapped[SummaryStatus] = mapped_column(
        enum_column(SummaryStatus),
        nullable=False,
        default=SummaryStatus.DRAFT,
        index=True,
    )
    generated_by: Mapped[int | None] = mapped_column(
        sa.ForeignKey("users.id", ondelete="SET NULL")
    )
    provider: Mapped[str] = mapped_column(sa.String(50), nullable=False)
    model: Mapped[str] = mapped_column(sa.String(200), nullable=False)
    sanitized_input: Mapped[str] = mapped_column(sa.Text, nullable=False)
    output: Mapped[dict[str, Any] | None] = mapped_column(sa.JSON)
    edited_text: Mapped[str | None] = mapped_column(sa.Text)
    overall_risk: Mapped[Severity | None] = mapped_column(enum_column(Severity))
    ai_analysis_id: Mapped[int | None] = mapped_column(
        sa.ForeignKey("ai_analyses.id", ondelete="SET NULL")
    )
    approved_by: Mapped[int | None] = mapped_column(
        sa.ForeignKey("users.id", ondelete="SET NULL")
    )
    approved_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
