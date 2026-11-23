"""Assessment registration, authorization and lifecycle."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Query
from sqlalchemy import func, or_, select

from app.core.deps import CurrentUser, DbSession, PaginationParams, get_assessment_or_404
from app.db.enums import AssessmentStatus
from app.db.models import Assessment
from app.schemas.assessments import (
    AssessmentCreate,
    AssessmentOut,
    AssessmentUpdate,
    ConfirmAuthorizationRequest,
)
from app.schemas.common import Page
from app.services import assessments as service

router = APIRouter(prefix="/assessments", tags=["Assessments"])


@router.post(
    "",
    response_model=AssessmentOut,
    status_code=201,
    summary="Create an assessment",
    description=(
        "Registers a target and its authorization reference. The assessment starts "
        "as a draft; scans stay blocked until authorization is confirmed."
    ),
)
async def create_assessment(
    payload: AssessmentCreate, db: DbSession, user: CurrentUser
) -> AssessmentOut:
    assessment = await service.create_assessment(db, payload, user)
    return AssessmentOut.model_validate(assessment)


@router.get(
    "",
    response_model=Page[AssessmentOut],
    summary="List assessments",
)
async def list_assessments(
    db: DbSession,
    user: CurrentUser,
    pagination: PaginationParams,
    q: Annotated[str | None, Query(max_length=200)] = None,
    status: Annotated[AssessmentStatus | None, Query()] = None,
) -> Page[AssessmentOut]:
    filters = []
    if q:
        needle = f"%{q.strip().lower()}%"
        filters.append(
            or_(
                Assessment.name.ilike(needle),
                Assessment.target_name.ilike(needle),
                Assessment.owner_name.ilike(needle),
            )
        )
    if status is not None:
        filters.append(Assessment.status == status)
    total = int(await db.scalar(select(func.count(Assessment.id)).where(*filters)) or 0)
    result = await db.execute(
        select(Assessment)
        .where(*filters)
        .order_by(Assessment.created_at.desc(), Assessment.id.desc())
        .offset(pagination.offset)
        .limit(pagination.page_size)
    )
    items = [AssessmentOut.model_validate(item) for item in result.scalars().all()]
    return Page[AssessmentOut](
        items=items, total=total, page=pagination.page, page_size=pagination.page_size
    )


@router.get(
    "/{assessment_id}",
    response_model=AssessmentOut,
    summary="Get one assessment",
)
async def get_assessment(
    assessment_id: int, db: DbSession, user: CurrentUser
) -> AssessmentOut:
    assessment = await get_assessment_or_404(db, assessment_id)
    return AssessmentOut.model_validate(assessment)


@router.patch(
    "/{assessment_id}",
    response_model=AssessmentOut,
    summary="Update assessment details or status",
)
async def update_assessment(
    assessment_id: int,
    payload: AssessmentUpdate,
    db: DbSession,
    user: CurrentUser,
) -> AssessmentOut:
    assessment = await get_assessment_or_404(db, assessment_id)
    updated = await service.update_assessment(db, assessment, payload, user)
    return AssessmentOut.model_validate(updated)


@router.post(
    "/{assessment_id}/confirm-authorization",
    response_model=AssessmentOut,
    summary="Record that the assessor confirmed authorization",
    description=(
        "Sets the confirmation flag, user and timestamp. Required before any scan. "
        "The authorization reference must already be recorded."
    ),
)
async def confirm_authorization(
    assessment_id: int,
    payload: ConfirmAuthorizationRequest,
    db: DbSession,
    user: CurrentUser,
) -> AssessmentOut:
    assessment = await get_assessment_or_404(db, assessment_id)
    updated = await service.confirm_authorization(db, assessment, user, payload.note)
    return AssessmentOut.model_validate(updated)


@router.post(
    "/{assessment_id}/archive",
    response_model=AssessmentOut,
    summary="Archive an assessment (no further scans or scope edits)",
)
async def archive_assessment(
    assessment_id: int, db: DbSession, user: CurrentUser
) -> AssessmentOut:
    assessment = await get_assessment_or_404(db, assessment_id)
    updated = await service.archive_assessment(db, assessment, user)
    return AssessmentOut.model_validate(updated)
