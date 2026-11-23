"""Append-only audit trail writes."""

from __future__ import annotations

from typing import Any

from fastapi.encoders import jsonable_encoder
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import AuditLog


async def record(
    db: AsyncSession,
    action: str,
    *,
    user_id: int | None = None,
    assessment_id: int | None = None,
    entity_type: str | None = None,
    entity_id: str | int | None = None,
    details: dict[str, Any] | None = None,
) -> AuditLog:
    """Add an audit row in the caller's transaction.

    The caller commits. No service updates or deletes audit rows.
    """
    row = AuditLog(
        action=action,
        user_id=user_id,
        assessment_id=assessment_id,
        entity_type=entity_type,
        entity_id=None if entity_id is None else str(entity_id),
        details=jsonable_encoder(details or {}),
    )
    db.add(row)
    await db.flush()
    return row
