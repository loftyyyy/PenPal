"""Scan lifecycle: request, list, inspect, cancel and download raw output."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from fastapi.responses import FileResponse
from sqlalchemy import func, select

from app.core.config import Settings, get_settings
from app.core.deps import CurrentUser, DbSession, PaginationParams, get_assessment_or_404
from app.core.errors import AppError, ConflictError, NotFoundError
from app.db.enums import ScanStatus, ScanTool
from app.db.models import Scan
from app.schemas.common import Page
from app.schemas.scans import ScanCreate, ScanOut, ScanQueuedOut
from app.services import scans as service
from app.services.scan_manager import ScanManager, get_scan_manager
from app.services.scope_guard import ScopeGuard
from app.services.storage import UnsafePathError, resolve_data_path

router = APIRouter(tags=["Scans"])

ScanManagerDep = Annotated[ScanManager, Depends(get_scan_manager)]


@router.post(
    "/assessments/{assessment_id}/scans",
    response_model=ScanQueuedOut,
    status_code=202,
    summary="Request an Nmap or ZAP scan",
    description=(
        "Validates the profile, target and ports, re-runs the scope guard, stores a "
        "queued scan and returns immediately. Only one scan per assessment may be "
        "queued or running at a time. Target reachability is checked again when the "
        "job starts."
    ),
)
async def request_scan(
    assessment_id: int,
    payload: ScanCreate,
    db: DbSession,
    user: CurrentUser,
    manager: ScanManagerDep,
    settings: Settings = Depends(get_settings),
) -> ScanQueuedOut:
    assessment = await get_assessment_or_404(db, assessment_id)
    scan = await service.create_scan(
        db, assessment, payload, user, ScopeGuard(settings)
    )
    await manager.start(scan.id)
    return ScanQueuedOut(scan_id=scan.id, status=scan.status)


@router.get(
    "/assessments/{assessment_id}/scans",
    response_model=Page[ScanOut],
    summary="List scans for an assessment",
)
async def list_scans(
    assessment_id: int,
    db: DbSession,
    user: CurrentUser,
    pagination: PaginationParams,
    status: Annotated[ScanStatus | None, Query()] = None,
    tool: Annotated[ScanTool | None, Query()] = None,
) -> Page[ScanOut]:
    await get_assessment_or_404(db, assessment_id)
    filters = [Scan.assessment_id == assessment_id]
    if status is not None:
        filters.append(Scan.status == status)
    if tool is not None:
        filters.append(Scan.tool == tool)
    total = int(await db.scalar(select(func.count(Scan.id)).where(*filters)) or 0)
    result = await db.execute(
        select(Scan)
        .where(*filters)
        .order_by(Scan.created_at.desc(), Scan.id.desc())
        .offset(pagination.offset)
        .limit(pagination.page_size)
    )
    items = [ScanOut.model_validate(scan) for scan in result.scalars().all()]
    return Page[ScanOut](
        items=items, total=total, page=pagination.page, page_size=pagination.page_size
    )


@router.get(
    "/scans/{scan_id}",
    response_model=ScanOut,
    summary="Get scan status and progress",
)
async def get_scan(scan_id: int, db: DbSession, user: CurrentUser) -> ScanOut:
    scan = await service.get_scan(db, scan_id)
    return ScanOut.model_validate(scan)


@router.post(
    "/scans/{scan_id}/cancel",
    response_model=ScanOut,
    summary="Cancel a queued or running scan",
    description=(
        "Marks the scan cancelled immediately and asks the running tool to stop. "
        "A completed or failed scan cannot be cancelled."
    ),
)
async def cancel_scan(
    scan_id: int, db: DbSession, user: CurrentUser, manager: ScanManagerDep
) -> ScanOut:
    scan = await service.get_scan(db, scan_id)
    if scan.status not in {ScanStatus.QUEUED, ScanStatus.RUNNING}:
        raise ConflictError(f"Scan is already {scan.status.value}")
    # Release the request session's read transaction before the manager writes
    # from its own session (important for SQLite in tests).
    await db.commit()
    await manager.cancel(scan_id)
    await db.refresh(scan)
    return ScanOut.model_validate(scan)


@router.get(
    "/scans/{scan_id}/raw",
    response_class=FileResponse,
    summary="Download the raw tool output",
    responses={
        200: {
            "description": "Raw Nmap XML or ZAP JSON",
            "content": {
                "application/xml": {},
                "application/json": {},
            },
        },
        404: {"description": "Scan or raw output not found"},
        409: {"description": "The scan has not produced raw output"},
    },
)
async def download_raw_output(
    scan_id: int,
    db: DbSession,
    user: CurrentUser,
    settings: Settings = Depends(get_settings),
) -> FileResponse:
    scan = await service.get_scan(db, scan_id)
    if not scan.raw_output_path:
        raise AppError(
            409,
            "raw_output_unavailable",
            "This scan has not stored raw tool output",
        )
    try:
        path = resolve_data_path(settings, scan.raw_output_path)
    except UnsafePathError as exc:
        raise NotFoundError("Raw output", scan_id) from exc
    if not path.is_file():
        raise NotFoundError("Raw output", scan_id)
    media_type = "application/xml" if scan.tool == ScanTool.NMAP else "application/json"
    return FileResponse(
        path,
        media_type=media_type,
        filename=Path(scan.raw_output_path).name,
    )
