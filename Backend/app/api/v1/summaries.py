"""Assessment summary generation, editing and approval."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query

from app.core.deps import (
    CurrentUser,
    DbSession,
    get_assessment_or_404,
)
from app.schemas.summary import SummaryBundle, SummaryEdit, SummaryOut
from app.services import summaries as service
from app.services.ai.manager import AIAnalysisManager, get_ai_manager

router = APIRouter(tags=["AI"])

AIManagerDep = Annotated[AIAnalysisManager, Depends(get_ai_manager)]


def _out(summary) -> SummaryOut:
    return SummaryOut(
        id=summary.id,
        assessment_id=summary.assessment_id,
        status=summary.status,
        provider=summary.provider,
        model=summary.model,
        output=summary.output,
        edited_text=summary.edited_text,
        text=service.summary_text(summary),
        overall_risk=summary.overall_risk,
        approved_by=summary.approved_by,
        approved_at=summary.approved_at,
        created_at=summary.created_at,
        updated_at=summary.updated_at,
    )


@router.post(
    "/assessments/{assessment_id}/summary/generate",
    response_model=SummaryOut,
    summary="Generate a draft assessment summary",
    description=(
        "Uses confirmed findings only. With zero confirmed findings, a deterministic "
        "summary is stored and the AI is not called. The assessor must approve it."
    ),
)
async def generate_summary(
    assessment_id: int,
    db: DbSession,
    user: CurrentUser,
    manager: AIManagerDep,
    force: Annotated[bool, Query(description="Bypass the AI cache")] = False,
) -> SummaryOut:
    assessment = await get_assessment_or_404(db, assessment_id)
    summary = await service.generate_summary(
        db, assessment, user, manager.service, force=force
    )
    return _out(summary)


@router.get(
    "/assessments/{assessment_id}/summary",
    response_model=SummaryBundle,
    summary="Latest assessment summary and history",
)
async def get_summary(
    assessment_id: int, db: DbSession, user: CurrentUser
) -> SummaryBundle:
    await get_assessment_or_404(db, assessment_id)
    rows = await service.list_summaries(db, assessment_id)
    return SummaryBundle(
        latest=_out(rows[0]) if rows else None,
        history=[_out(row) for row in rows],
    )


@router.patch(
    "/summaries/{summary_id}",
    response_model=SummaryOut,
    summary="Edit a draft summary",
    description=(
        "Editing an approved summary resets it to draft and clears approval so it must "
        "be approved again."
    ),
)
async def edit_summary(
    summary_id: int,
    payload: SummaryEdit,
    db: DbSession,
    user: CurrentUser,
) -> SummaryOut:
    summary = await service.get_summary(db, summary_id)
    updated = await service.edit_summary(db, summary, payload, user)
    return _out(updated)


@router.post(
    "/summaries/{summary_id}/approve",
    response_model=SummaryOut,
    summary="Approve a summary for the report",
    description=(
        "Approving supersedes the previously approved summary for the assessment. "
        "Only the approved summary is used in the report."
    ),
)
async def approve_summary(
    summary_id: int, db: DbSession, user: CurrentUser
) -> SummaryOut:
    summary = await service.get_summary(db, summary_id)
    updated = await service.approve_summary(db, summary, user)
    return _out(updated)
