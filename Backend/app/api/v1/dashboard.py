"""Assessment dashboard aggregate."""

from __future__ import annotations

from fastapi import APIRouter

from app.core.deps import CurrentUser, DbSession, get_assessment_or_404
from app.schemas.dashboard import DashboardOut
from app.services.dashboard import build_dashboard

router = APIRouter(tags=["Dashboard"])


@router.get(
    "/assessments/{assessment_id}/dashboard",
    response_model=DashboardOut,
    summary="Assessment dashboard metrics",
    description=(
        "Severity counts use final severity for confirmed findings and AI-suggested "
        "or tool severity otherwise. Includes verification, category, scan and AI "
        "coverage data without per-finding queries."
    ),
)
async def get_dashboard(
    assessment_id: int, db: DbSession, user: CurrentUser
) -> DashboardOut:
    assessment = await get_assessment_or_404(db, assessment_id)
    return await build_dashboard(db, assessment)
