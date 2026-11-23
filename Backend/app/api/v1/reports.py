"""Assessment report generation, listing and download."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends
from fastapi.responses import FileResponse

from app.core.config import Settings, get_settings
from app.core.deps import (
    CurrentUser,
    DbSession,
    PaginationParams,
    get_assessment_or_404,
)
from app.core.errors import AppError, NotFoundError
from app.db.enums import ReportFormat, ReportStatus
from app.db.models import Report
from app.schemas.common import Page
from app.schemas.reports import ReportCreate, ReportOut
from app.services import report_builder
from app.services.storage import UnsafePathError, resolve_data_path

router = APIRouter(tags=["Reports"])


def _out(report: Report) -> ReportOut:
    return ReportOut(
        id=report.id,
        assessment_id=report.assessment_id,
        format=report.format,
        status=report.status,
        sha256=report.sha256,
        generated_by=report.generated_by,
        summary_counts=report.summary_counts,
        error=report.error,
        has_file=bool(report.file_path),
        created_at=report.created_at,
        updated_at=report.updated_at,
    )


@router.post(
    "/assessments/{assessment_id}/reports",
    response_model=ReportOut,
    status_code=201,
    summary="Generate an HTML or PDF assessment report",
    description=(
        "Builds the report from assessor-confirmed findings only. If PDF rendering "
        "fails, a ready HTML report is returned instead and the report row records why."
    ),
)
async def create_report(
    assessment_id: int,
    payload: ReportCreate,
    db: DbSession,
    user: CurrentUser,
    settings: Annotated[Settings, Depends(get_settings)],
) -> ReportOut:
    assessment = await get_assessment_or_404(db, assessment_id)
    report = await report_builder.create_report(
        db,
        assessment,
        report_format=payload.format,
        user=user,
        settings=settings,
    )
    return _out(report)


@router.get(
    "/assessments/{assessment_id}/reports",
    response_model=Page[ReportOut],
    summary="List generated reports",
)
async def list_reports(
    assessment_id: int,
    db: DbSession,
    user: CurrentUser,
    pagination: PaginationParams,
) -> Page[ReportOut]:
    await get_assessment_or_404(db, assessment_id)
    rows, total = await report_builder.list_reports(
        db, assessment_id, offset=pagination.offset, limit=pagination.page_size
    )
    return Page[ReportOut](
        items=[_out(row) for row in rows],
        total=total,
        page=pagination.page,
        page_size=pagination.page_size,
    )


@router.get(
    "/reports/{report_id}/download",
    response_class=FileResponse,
    summary="Download a generated report",
    responses={
        200: {"description": "HTML or PDF report"},
        404: {"description": "Report or file not found"},
        409: {"description": "Report is not ready"},
    },
)
async def download_report(
    report_id: int,
    db: DbSession,
    user: CurrentUser,
    settings: Annotated[Settings, Depends(get_settings)],
) -> FileResponse:
    report = await db.get(Report, report_id)
    if report is None:
        raise NotFoundError("Report", report_id)
    if report.status != ReportStatus.READY or not report.file_path:
        raise AppError(
            409,
            "report_not_ready",
            f"Report is {report.status.value} and has no downloadable file",
        )
    try:
        path = resolve_data_path(settings, report.file_path)
    except UnsafePathError as exc:
        raise NotFoundError("Report", report_id) from exc
    if not path.is_file():
        raise NotFoundError("Report", report_id)
    media_type = (
        "application/pdf"
        if report.format == ReportFormat.PDF
        else "text/html"
    )
    return FileResponse(
        Path(path), media_type=media_type, filename=Path(report.file_path).name
    )
