from __future__ import annotations

from typing import Any

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, enum_column
from app.db.enums import AIAnalysisStatus, AIFunction


class AIAnalysis(TimestampMixin, Base):
    __tablename__ = "ai_analyses"
    __table_args__ = (sa.Index("ix_ai_analyses_hash", "input_hash"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    finding_id: Mapped[int | None] = mapped_column(
        sa.ForeignKey("findings.id", ondelete="CASCADE"), nullable=True, index=True
    )
    assessment_id: Mapped[int | None] = mapped_column(
        sa.ForeignKey("assessments.id", ondelete="CASCADE"), nullable=True, index=True
    )
    function: Mapped[AIFunction] = mapped_column(enum_column(AIFunction), nullable=False)
    provider: Mapped[str] = mapped_column(sa.String(50), nullable=False)
    model: Mapped[str] = mapped_column(sa.String(200), nullable=False)
    prompt_version: Mapped[str] = mapped_column(sa.String(50), nullable=False)
    input_hash: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    sanitized_input: Mapped[str] = mapped_column(sa.Text, nullable=False)
    output: Mapped[dict[str, Any] | None] = mapped_column(sa.JSON)
    status: Mapped[AIAnalysisStatus] = mapped_column(
        enum_column(AIAnalysisStatus), nullable=False
    )
    error: Mapped[str | None] = mapped_column(sa.Text)
    latency_ms: Mapped[int | None] = mapped_column(sa.Integer)
    prompt_tokens: Mapped[int | None] = mapped_column(sa.Integer)
    completion_tokens: Mapped[int | None] = mapped_column(sa.Integer)
    redaction_report: Mapped[dict[str, Any] | None] = mapped_column(sa.JSON)
    attempts: Mapped[list[dict[str, Any]] | None] = mapped_column(sa.JSON)

    finding: Mapped["Finding | None"] = relationship(  # noqa: F821, UP037
        back_populates="ai_analyses"
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"AIAnalysis(id={self.id!r}, function={self.function!r}, status={self.status!r})"
