from __future__ import annotations

from datetime import datetime
from typing import Any

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, enum_column
from app.db.enums import AssessmentStatus, ScopeKind


class Assessment(TimestampMixin, Base):
    __tablename__ = "assessments"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(sa.String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(sa.Text)
    target_name: Mapped[str] = mapped_column(sa.String(200), nullable=False)
    target_base_url: Mapped[str | None] = mapped_column(sa.String(2048))
    target_description: Mapped[str | None] = mapped_column(sa.Text)
    owner_name: Mapped[str] = mapped_column(sa.String(200), nullable=False)
    authorization_reference: Mapped[str] = mapped_column(sa.Text, nullable=False)
    authorization_confirmed: Mapped[bool] = mapped_column(
        sa.Boolean, nullable=False, default=False
    )
    authorization_confirmed_by: Mapped[int | None] = mapped_column(
        sa.ForeignKey("users.id", ondelete="SET NULL")
    )
    authorization_confirmed_at: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True)
    )
    hosting_environment: Mapped[str | None] = mapped_column(sa.String(200))
    selected_categories: Mapped[list[str]] = mapped_column(
        sa.JSON, nullable=False, default=list
    )
    status: Mapped[AssessmentStatus] = mapped_column(
        enum_column(AssessmentStatus), nullable=False, default=AssessmentStatus.DRAFT
    )
    created_by: Mapped[int] = mapped_column(
        sa.ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True
    )

    scope_items: Mapped[list[ScopeItem]] = relationship(
        back_populates="assessment", cascade="all, delete-orphan", lazy="selectin"
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"Assessment(id={self.id!r}, name={self.name!r})"


class ScopeItem(TimestampMixin, Base):
    __tablename__ = "scope_items"
    __table_args__ = (
        sa.UniqueConstraint("assessment_id", "kind", "value", name="uq_scope_item"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    assessment_id: Mapped[int] = mapped_column(
        sa.ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False, index=True
    )
    kind: Mapped[ScopeKind] = mapped_column(enum_column(ScopeKind), nullable=False)
    value: Mapped[str] = mapped_column(sa.String(2048), nullable=False)
    in_scope: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=True)
    note: Mapped[str | None] = mapped_column(sa.String(500))

    assessment: Mapped[Assessment] = relationship(back_populates="scope_items")

    def __repr__(self) -> str:  # pragma: no cover
        return f"ScopeItem(id={self.id!r}, kind={self.kind!r}, value={self.value!r})"


# Re-export for typing tools that resolve annotations at runtime.
_ = Any
