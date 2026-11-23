"""Finding listing, manual findings, verification and evidence."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, File, Form, Query, UploadFile

from app.core.config import Settings, get_settings
from app.core.deps import (
    CurrentUser,
    DbSession,
    PaginationParams,
    get_assessment_or_404,
    get_finding_or_404,
)
from app.core.errors import AppError
from app.db.enums import (
    FindingCategory,
    FindingSource,
    Severity,
    VerificationStatus,
)
from app.schemas.common import Page
from app.schemas.findings import (
    EvidenceOut,
    FindingDetailOut,
    FindingOut,
    FindingSortField,
    FindingVerify,
    ManualFindingCreate,
    SortOrder,
)
from app.services import evidence as evidence_service
from app.services import findings as finding_service
from app.services import verification as verification_service

router = APIRouter(tags=["Findings"])


@router.get(
    "/assessments/{assessment_id}/findings",
    response_model=Page[FindingOut],
    summary="List findings with filters and sorting",
    description=(
        "Severity filters and sorting use the effective severity: final severity for "
        "confirmed findings, otherwise AI-suggested severity, otherwise tool severity."
    ),
)
async def list_findings(
    assessment_id: int,
    db: DbSession,
    user: CurrentUser,
    pagination: PaginationParams,
    severity: Annotated[Severity | None, Query()] = None,
    status: Annotated[VerificationStatus | None, Query()] = None,
    category: Annotated[FindingCategory | None, Query()] = None,
    source: Annotated[FindingSource | None, Query()] = None,
    q: Annotated[str | None, Query(max_length=200)] = None,
    sort: Annotated[FindingSortField, Query()] = FindingSortField.CREATED_AT,
    order: Annotated[SortOrder, Query()] = SortOrder.DESC,
) -> Page[FindingOut]:
    await get_assessment_or_404(db, assessment_id)
    rows, total = await finding_service.list_findings(
        db,
        assessment_id,
        severity=severity,
        verification_status=status,
        category=category,
        source=source,
        query=q,
        sort=sort,
        order=order,
        offset=pagination.offset,
        limit=pagination.page_size,
    )
    return Page[FindingOut](
        items=[FindingOut.model_validate(row) for row in rows],
        total=total,
        page=pagination.page,
        page_size=pagination.page_size,
    )


@router.get(
    "/findings/{finding_id}",
    response_model=FindingDetailOut,
    summary="Get one finding",
)
async def get_finding(
    finding_id: int, db: DbSession, user: CurrentUser
) -> FindingDetailOut:
    finding = await get_finding_or_404(db, finding_id)
    return FindingDetailOut.model_validate(finding)


@router.post(
    "/assessments/{assessment_id}/findings",
    response_model=FindingDetailOut,
    status_code=201,
    summary="Create a manual finding",
    description=(
        "Manual findings start pending, are attributed to the assessor, and never "
        "set final severity or verification state."
    ),
)
async def create_manual_finding(
    assessment_id: int,
    payload: ManualFindingCreate,
    db: DbSession,
    user: CurrentUser,
) -> FindingDetailOut:
    assessment = await get_assessment_or_404(db, assessment_id)
    finding = await finding_service.create_manual_finding(
        db, assessment, payload, user
    )
    return FindingDetailOut.model_validate(finding)


@router.patch(
    "/findings/{finding_id}/verify",
    response_model=FindingDetailOut,
    summary="Record the assessor's verification decision",
    description=(
        "False positives need a reason of at least 10 characters. Confirmed findings "
        "need a final severity or fall back to AI/tool severity with an audit note. "
        "AI output can never set these fields."
    ),
)
async def verify_finding(
    finding_id: int,
    payload: FindingVerify,
    db: DbSession,
    user: CurrentUser,
) -> FindingDetailOut:
    finding = await get_finding_or_404(db, finding_id)
    updated = await verification_service.verify_finding(db, finding, payload, user)
    return FindingDetailOut.model_validate(updated)


@router.post(
    "/findings/{finding_id}/evidence",
    response_model=EvidenceOut,
    status_code=201,
    summary="Add a note or upload evidence for a finding",
    description=(
        "Send either a note or one file (png, jpg, jpeg, txt, pdf). Files are "
        "size-limited, checked against their extension and MIME type, stored under a "
        "random name, and hashed."
    ),
)
async def add_evidence(
    finding_id: int,
    db: DbSession,
    user: CurrentUser,
    settings: Annotated[Settings, Depends(get_settings)],
    file: Annotated[UploadFile | None, File(description="Evidence file")] = None,
    note: Annotated[str | None, Form(description="Text evidence note")] = None,
) -> EvidenceOut:
    finding = await get_finding_or_404(db, finding_id)
    if (file is None) == (note is None):
        raise AppError(
            422,
            "invalid_evidence",
            "Provide exactly one of: a file or a note",
        )
    if file is not None:
        data = await file.read(settings.max_upload_bytes + 1)
        evidence = await evidence_service.add_file(
            db,
            finding,
            filename=file.filename or "upload",
            content_type=file.content_type,
            data=data,
            user=user,
            settings=settings,
        )
    else:
        evidence = await evidence_service.add_note(
            db, finding, note or "", user, settings
        )
    return EvidenceOut.from_evidence(evidence)


@router.get(
    "/findings/{finding_id}/evidence",
    response_model=list[EvidenceOut],
    summary="List evidence for a finding",
)
async def list_evidence(
    finding_id: int, db: DbSession, user: CurrentUser
) -> list[EvidenceOut]:
    await get_finding_or_404(db, finding_id)
    rows = await evidence_service.list_evidence(db, finding_id)
    return [EvidenceOut.from_evidence(row) for row in rows]
