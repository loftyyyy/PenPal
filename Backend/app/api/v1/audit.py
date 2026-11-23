"""Append-only audit log read endpoint."""

from __future__ import annotations

from fastapi import APIRouter
from sqlalchemy import func, select

from app.core.deps import (
    CurrentUser,
    DbSession,
    PaginationParams,
    get_assessment_or_404,
)
from app.db.models import AuditLog
from app.schemas.audit import AuditLogOut
from app.schemas.common import Page

router = APIRouter(tags=["Audit"])


@router.get(
    "/assessments/{assessment_id}/audit-log",
    response_model=Page[AuditLogOut],
    summary="Read the assessment audit trail",
    description="Newest first. Audit rows are append-only and never updated or deleted.",
)
async def list_audit_log(
    assessment_id: int,
    db: DbSession,
    user: CurrentUser,
    pagination: PaginationParams,
) -> Page[AuditLogOut]:
    await get_assessment_or_404(db, assessment_id)
    total = int(
        await db.scalar(
            select(func.count(AuditLog.id)).where(
                AuditLog.assessment_id == assessment_id
            )
        )
        or 0
    )
    rows = (
        (
            await db.execute(
                select(AuditLog)
                .where(AuditLog.assessment_id == assessment_id)
                .order_by(AuditLog.created_at.desc(), AuditLog.id.desc())
                .offset(pagination.offset)
                .limit(pagination.page_size)
            )
        )
        .scalars()
        .all()
    )
    return Page[AuditLogOut](
        items=[AuditLogOut.model_validate(row) for row in rows],
        total=total,
        page=pagination.page,
        page_size=pagination.page_size,
    )
