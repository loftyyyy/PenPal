"""Append-only audit log read endpoint."""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Query
from fastapi.encoders import jsonable_encoder
from fastapi.responses import Response
from sqlalchemy import and_, func, or_, select

from app.core.deps import (
    CurrentUser,
    DbSession,
    PaginationParams,
    get_assessment_or_404,
)
from app.db.enums import AuditOutcome
from app.db.models import AuditLog
from app.schemas.audit import AuditLogOut
from app.schemas.common import Page

router = APIRouter(tags=["Audit"])


def _filters(
    assessment_id: int,
    *,
    action: str | None,
    entity_type: str | None,
    user_id: int | None,
    outcome: AuditOutcome | None,
    from_date: datetime | None,
    to_date: datetime | None,
):
    filters = [AuditLog.assessment_id == assessment_id]
    if action:
        filters.append(AuditLog.action == action)
    if entity_type:
        filters.append(AuditLog.entity_type == entity_type)
    if user_id is not None:
        filters.append(AuditLog.user_id == user_id)
    if from_date is not None:
        filters.append(AuditLog.created_at >= from_date)
    if to_date is not None:
        filters.append(AuditLog.created_at <= to_date)
    if outcome is not None:
        allowed = AuditLog.details["allowed"].as_boolean() == True  # noqa: E712
        if outcome == AuditOutcome.DENIED:
            filters.append(
                or_(
                    AuditLog.action == "scan.scope_denied",
                    and_(AuditLog.action == "scope.checked", allowed.is_(False)),
                )
            )
        else:
            filters.append(
                and_(AuditLog.action == "scope.checked", allowed.is_(True))
            )
    return filters


def _csv_cell(value: object) -> str:
    text = "" if value is None else str(value)
    if text.startswith(("=", "+", "-", "@")):
        return "'" + text
    return text


@router.get(
    "/assessments/{assessment_id}/audit-log",
    response_model=Page[AuditLogOut],
    summary="Read the assessment audit trail",
    description=(
        "Newest first. Audit rows are append-only and never updated or deleted. "
        "Filters: action, entity_type, user_id, outcome (scope allow/deny), from, to."
    ),
)
async def list_audit_log(
    assessment_id: int,
    db: DbSession,
    user: CurrentUser,
    pagination: PaginationParams,
    action: Annotated[str | None, Query(max_length=100)] = None,
    entity_type: Annotated[str | None, Query(max_length=50)] = None,
    user_id: Annotated[int | None, Query(ge=1)] = None,
    outcome: Annotated[AuditOutcome | None, Query()] = None,
    from_date: Annotated[
        datetime | None, Query(alias="from", description="ISO date/time, inclusive")
    ] = None,
    to_date: Annotated[
        datetime | None, Query(alias="to", description="ISO date/time, inclusive")
    ] = None,
) -> Page[AuditLogOut]:
    await get_assessment_or_404(db, assessment_id)
    filters = _filters(
        assessment_id,
        action=action,
        entity_type=entity_type,
        user_id=user_id,
        outcome=outcome,
        from_date=from_date,
        to_date=to_date,
    )
    total = int(
        await db.scalar(select(func.count(AuditLog.id)).where(*filters)) or 0
    )
    rows = (
        (
            await db.execute(
                select(AuditLog)
                .where(*filters)
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


@router.get(
    "/assessments/{assessment_id}/audit-log/export",
    summary="Export the filtered audit trail",
    description=(
        "CSV or JSON export of the filtered audit log. CSV cells starting with "
        "=, +, - or @ are prefixed with a quote to prevent spreadsheet formula injection."
    ),
)
async def export_audit_log(
    assessment_id: int,
    db: DbSession,
    user: CurrentUser,
    action: Annotated[str | None, Query(max_length=100)] = None,
    entity_type: Annotated[str | None, Query(max_length=50)] = None,
    user_id: Annotated[int | None, Query(ge=1)] = None,
    outcome: Annotated[AuditOutcome | None, Query()] = None,
    from_date: Annotated[datetime | None, Query(alias="from")] = None,
    to_date: Annotated[datetime | None, Query(alias="to")] = None,
    format: Annotated[str, Query(pattern="^(csv|json)$")] = "csv",
) -> Response:
    await get_assessment_or_404(db, assessment_id)
    filters = _filters(
        assessment_id,
        action=action,
        entity_type=entity_type,
        user_id=user_id,
        outcome=outcome,
        from_date=from_date,
        to_date=to_date,
    )
    rows = (
        (
            await db.execute(
                select(AuditLog)
                .where(*filters)
                .order_by(AuditLog.created_at.asc(), AuditLog.id.asc())
            )
        )
        .scalars()
        .all()
    )
    if format == "json":
        payload = [
            jsonable_encoder(AuditLogOut.model_validate(row)) for row in rows
        ]
        return Response(
            content=json.dumps(payload, default=str),
            media_type="application/json",
            headers={
                "Content-Disposition": (
                    f'attachment; filename="audit-log-{assessment_id}.json"'
                )
            },
        )

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        [
            "id",
            "created_at",
            "user_id",
            "action",
            "entity_type",
            "entity_id",
            "details",
        ]
    )
    for row in rows:
        writer.writerow(
            [
                row.id,
                row.created_at.isoformat() if row.created_at else "",
                row.user_id,
                _csv_cell(row.action),
                _csv_cell(row.entity_type),
                _csv_cell(row.entity_id),
                _csv_cell(json.dumps(row.details, default=str)),
            ]
        )
    return Response(
        content=buffer.getvalue(),
        media_type="text/csv",
        headers={
            "Content-Disposition": (
                f'attachment; filename="audit-log-{assessment_id}.csv"'
            )
        },
    )
