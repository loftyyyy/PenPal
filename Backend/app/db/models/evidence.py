from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, enum_column
from app.db.enums import EvidenceType


class Evidence(TimestampMixin, Base):
    __tablename__ = "evidence"

    id: Mapped[int] = mapped_column(primary_key=True)
    finding_id: Mapped[int | None] = mapped_column(
        sa.ForeignKey("findings.id", ondelete="CASCADE"), nullable=True, index=True
    )
    scan_id: Mapped[int | None] = mapped_column(
        sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=True, index=True
    )
    type: Mapped[EvidenceType] = mapped_column(enum_column(EvidenceType), nullable=False)
    content: Mapped[str | None] = mapped_column(sa.Text)
    file_path: Mapped[str | None] = mapped_column(sa.String(1024))
    sha256: Mapped[str | None] = mapped_column(sa.String(64))
    created_by: Mapped[int | None] = mapped_column(
        sa.ForeignKey("users.id", ondelete="SET NULL")
    )

    finding: Mapped["Finding | None"] = relationship(  # noqa: F821, UP037
        back_populates="evidence"
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"Evidence(id={self.id!r}, type={self.type!r})"
