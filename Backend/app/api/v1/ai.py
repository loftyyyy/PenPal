"""Advisory AI interpretation and remediation endpoints."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import (
    CurrentUser,
    DbSession,
    get_assessment_or_404,
    get_finding_or_404,
)
from app.core.errors import ConflictError
from app.db.enums import (
    SEVERITY_ORDER,
    AIAnalysisStatus,
    AIFunction,
    Severity,
)
from app.db.models import AIAnalysis, Finding
from app.schemas.ai import (
    AIAnalysisOut,
    AIJobOut,
    AIStatusOut,
    BulkAnalyzeQueued,
    BulkAnalyzeRequest,
    FindingAnalysisOut,
)
from app.services import audit
from app.services.ai.manager import AIAnalysisManager, get_ai_manager

router = APIRouter(tags=["AI"])

AIManagerDep = Annotated[AIAnalysisManager, Depends(get_ai_manager)]


@router.post(
    "/findings/{finding_id}/analyze",
    response_model=FindingAnalysisOut,
    summary="Run interpretation and remediation for one finding",
    description=(
        "Runs both advisory AI functions on redacted evidence. AI output never sets "
        "the final severity or verification state. Provider failures are stored per "
        "function and do not fail the request."
    ),
)
async def analyze_finding(
    finding_id: int,
    db: DbSession,
    user: CurrentUser,
    manager: AIManagerDep,
    force: Annotated[bool, Query(description="Bypass the AI cache")] = False,
) -> FindingAnalysisOut:
    finding = await get_finding_or_404(db, finding_id)
    analyses = await manager.service.analyze_finding(
        db, finding, user_id=user.id, force=force
    )
    await db.commit()
    return FindingAnalysisOut(
        finding_id=finding.id,
        analyses=[AIAnalysisOut.model_validate(analysis) for analysis in analyses],
    )


@router.post(
    "/assessments/{assessment_id}/analyze",
    response_model=BulkAnalyzeQueued,
    status_code=202,
    summary="Queue bulk analysis for an assessment",
    description=(
        "Queues a background job over matching findings. Progress is available at "
        "GET /assessments/{id}/ai-status. Only one bulk job runs per assessment."
    ),
)
async def bulk_analyze(
    assessment_id: int,
    payload: BulkAnalyzeRequest,
    db: DbSession,
    user: CurrentUser,
    manager: AIManagerDep,
) -> BulkAnalyzeQueued:
    await get_assessment_or_404(db, assessment_id)
    filters = [Finding.assessment_id == assessment_id]
    if payload.only_unanalyzed:
        analyzed = select(AIAnalysis.finding_id).where(
            AIAnalysis.function == AIFunction.INTERPRET,
            AIAnalysis.status == AIAnalysisStatus.SUCCESS,
        )
        filters.append(Finding.id.not_in(analyzed))
    rows = (
        await db.execute(
            select(
                Finding.id,
                Finding.final_severity,
                Finding.ai_suggested_severity,
                Finding.tool_severity,
            ).where(*filters)
        )
    ).all()
    selected: list[int] = []
    for row in rows:
        severity = (
            row.final_severity
            or row.ai_suggested_severity
            or row.tool_severity
        )
        if (
            payload.min_severity is not None
            and severity is not None
            and SEVERITY_ORDER[Severity(severity)] < SEVERITY_ORDER[payload.min_severity]
        ):
            continue
        selected.append(row.id)
    if not selected:
        raise ConflictError("No findings match the bulk analysis filters")

    job = await manager.start_bulk(
        assessment_id=assessment_id,
        requested_by=user.id,
        finding_ids=selected,
        force=payload.force,
    )
    await audit.record(
        db,
        "ai.bulk_requested",
        user_id=user.id,
        assessment_id=assessment_id,
        entity_type="assessment",
        entity_id=assessment_id,
        details={
            "job_id": job.id,
            "total": len(selected),
            "min_severity": (
                payload.min_severity.value if payload.min_severity else None
            ),
            "only_unanalyzed": payload.only_unanalyzed,
        },
    )
    await db.commit()
    return BulkAnalyzeQueued(
        job_id=job.id,
        assessment_id=assessment_id,
        status=job.status,
        total=job.total,
    )


@router.get(
    "/assessments/{assessment_id}/ai-status",
    response_model=AIStatusOut,
    summary="Bulk analysis progress and coverage",
)
async def ai_status(
    assessment_id: int,
    db: DbSession,
    user: CurrentUser,
    manager: AIManagerDep,
) -> AIStatusOut:
    await get_assessment_or_404(db, assessment_id)
    total = int(
        await db.scalar(
            select(func.count(Finding.id)).where(
                Finding.assessment_id == assessment_id
            )
        )
        or 0
    )
    interpreted = await _successful_count(db, assessment_id, AIFunction.INTERPRET)
    remediated = await _successful_count(db, assessment_id, AIFunction.REMEDIATE)
    last_analyzed_at = await db.scalar(
        select(func.max(AIAnalysis.created_at))
        .join(Finding, Finding.id == AIAnalysis.finding_id)
        .where(Finding.assessment_id == assessment_id)
    )
    job = manager.latest_for_assessment(assessment_id)
    return AIStatusOut(
        assessment_id=assessment_id,
        total_findings=total,
        findings_with_interpretation=interpreted,
        findings_with_remediation=remediated,
        pending_findings=max(0, total - interpreted),
        last_analyzed_at=last_analyzed_at,
        job=AIJobOut.from_job(job) if job is not None else None,
    )


@router.get(
    "/findings/{finding_id}/ai-analyses",
    response_model=list[AIAnalysisOut],
    summary="List AI analyses for a finding",
    description=(
        "Returns every attempt newest first, including the exact sanitized input that "
        "was sent and its redaction report."
    ),
)
async def list_analyses(
    finding_id: int,
    db: DbSession,
    user: CurrentUser,
) -> list[AIAnalysisOut]:
    await get_finding_or_404(db, finding_id)
    rows = (
        (
            await db.execute(
                select(AIAnalysis)
                .where(AIAnalysis.finding_id == finding_id)
                .order_by(AIAnalysis.created_at.desc(), AIAnalysis.id.desc())
            )
        )
        .scalars()
        .all()
    )
    return [AIAnalysisOut.model_validate(row) for row in rows]


async def _successful_count(
    db: AsyncSession, assessment_id: int, function: AIFunction
) -> int:
    return int(
        await db.scalar(
            select(func.count(func.distinct(AIAnalysis.finding_id)))
            .join(Finding, Finding.id == AIAnalysis.finding_id)
            .where(
                Finding.assessment_id == assessment_id,
                AIAnalysis.function == function,
                AIAnalysis.status == AIAnalysisStatus.SUCCESS,
            )
        )
        or 0
    )
