from __future__ import annotations

from typing import Any

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin


class HttpCheckConfig(TimestampMixin, Base):
    __tablename__ = "http_check_configs"

    id: Mapped[int] = mapped_column(primary_key=True)
    assessment_id: Mapped[int] = mapped_column(
        sa.ForeignKey("assessments.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
    )
    login: Mapped[dict[str, Any] | None] = mapped_column(sa.JSON)
    access_rules: Mapped[list[dict[str, Any]]] = mapped_column(
        sa.JSON, nullable=False, default=list
    )
    roles: Mapped[list[str]] = mapped_column(sa.JSON, nullable=False, default=list)
    limits: Mapped[dict[str, Any]] = mapped_column(
        sa.JSON, nullable=False, default=dict
    )
    updated_by: Mapped[int | None] = mapped_column(
        sa.ForeignKey("users.id", ondelete="SET NULL")
    )


class TestAccount(TimestampMixin, Base):
    __tablename__ = "test_accounts"
    __table_args__ = (
        sa.UniqueConstraint(
            "assessment_id", "role", "username", name="uq_test_account"
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    assessment_id: Mapped[int] = mapped_column(
        sa.ForeignKey("assessments.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    role: Mapped[str] = mapped_column(sa.String(50), nullable=False)
    username: Mapped[str] = mapped_column(sa.String(200), nullable=False)
    password_encrypted: Mapped[str] = mapped_column(sa.Text, nullable=False)
    created_by: Mapped[int | None] = mapped_column(
        sa.ForeignKey("users.id", ondelete="SET NULL")
    )
