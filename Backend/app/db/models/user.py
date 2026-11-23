from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, enum_column
from app.db.enums import Role


class User(TimestampMixin, Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(sa.String(255), unique=True, index=True, nullable=False)
    full_name: Mapped[str] = mapped_column(sa.String(200), nullable=False)
    password_hash: Mapped[str] = mapped_column(sa.String(255), nullable=False)
    role: Mapped[Role] = mapped_column(enum_column(Role), nullable=False, default=Role.ASSESSOR)
    is_active: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=True)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"User(id={self.id!r}, email={self.email!r}, role={self.role!r})"
