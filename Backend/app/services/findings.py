"""Finding queries, manual findings and effective severity."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import case, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql.elements import ColumnElement

from app.core.errors import AppError, ConflictError
from app.db.base import utcnow
from app.db.enums import (
    SEVERITY_ORDER,
    FindingCategory,
    FindingSource,
    Severity,
    VerificationStatus,
)
from app.db.models import Assessment, Finding, User
from app.schemas.findings import (
    FindingSortField,
    ManualFindingCreate,
    SortOrder,
)
from app.services import audit
from app.services.finding_normalizer import fingerprint


def effective_severity_expr() -> ColumnElement[str]:
    """Confirmed findings use final severity; others prefer AI, then tool."""
    return case(
        (
            Finding.verification_status == VerificationStatus.CONFIRMED,
            Finding.final_severity,
        ),
        (Finding.ai_suggested_severity.is_not(None), Finding.ai_suggested_severity),
        else_=Finding.tool_severity,
    )


def severity_rank_expr(value: ColumnElement[str]) -> ColumnElement[int]:
    return case(
        *[(value == severity.value, rank) for severity, rank in SEVERITY_ORDER.items()],
        else_=0,
    )


async def get_finding(db: AsyncSession, finding_id: int) -> Finding | None:
    return await db.get(Finding, finding_id)


async def create_manual_finding(
    db: AsyncSession,
    assessment: Assessment,
    payload: ManualFindingCreate,
    user: User,
) -> Finding:
    title = payload.title.strip()
    if not title:
        raise AppError(422, "invalid_finding", "Finding title must not be blank")
    method = payload.http_method.strip().upper() if payload.http_method else None
    parameter = payload.parameter.strip() if payload.parameter else None
    affected_url = payload.affected_url.strip() if payload.affected_url else None
    digest = fingerprint(
        FindingSource.MANUAL.value,
        f"manual:{title.lower()}",
        method,
        affected_url,
        parameter,
    )
    duplicate = await db.scalar(
        select(Finding.id).where(
            Finding.assessment_id == assessment.id,
            Finding.fingerprint == digest,
        )
    )
    if duplicate is not None:
        raise ConflictError(
            "A manual finding with the same title, endpoint and parameter already exists"
        )
    now = utcnow()
    finding = Finding(
        assessment_id=assessment.id,
        source=FindingSource.MANUAL,
        fingerprint=digest,
        title=title[:500],
        description=payload.description,
        category=payload.category,
        owasp_category=payload.owasp_category,
        cwe=payload.cwe,
        affected_url=affected_url[:2048] if affected_url else None,
        http_method=method[:20] if method else None,
        parameter=parameter[:200] if parameter else None,
        tool_severity=payload.severity,
        tool_confidence="manual",
        verification_status=VerificationStatus.PENDING,
        first_seen_at=now,
        last_seen_at=now,
        seen_count=1,
        raw={"manual": True, "entered_by": user.id},
    )
    db.add(finding)
    await db.flush()
    await audit.record(
        db,
        "finding.created",
        user_id=user.id,
        assessment_id=assessment.id,
        entity_type="finding",
        entity_id=finding.id,
        details={
            "source": FindingSource.MANUAL.value,
            "title": finding.title,
            "category": payload.category.value,
            "severity": payload.severity.value,
        },
    )
    await db.commit()
    await db.refresh(finding)
    return finding


async def list_findings(
    db: AsyncSession,
    assessment_id: int,
    *,
    severity: Severity | None,
    verification_status: VerificationStatus | None,
    category: FindingCategory | None,
    source: FindingSource | None,
    query: str | None,
    sort: FindingSortField,
    order: SortOrder,
    offset: int,
    limit: int,
) -> tuple[list[Finding], int]:
    filters = [Finding.assessment_id == assessment_id]
    if severity is not None:
        filters.append(effective_severity_expr() == severity.value)
    if verification_status is not None:
        filters.append(Finding.verification_status == verification_status)
    if category is not None:
        filters.append(Finding.category == category)
    if source is not None:
        filters.append(Finding.source == source)
    if query and query.strip():
        pattern = f"%{query.strip()}%"
        filters.append(
            or_(
                Finding.title.ilike(pattern),
                Finding.description.ilike(pattern),
                Finding.affected_url.ilike(pattern),
                Finding.parameter.ilike(pattern),
            )
        )

    total = int(
        await db.scalar(select(func.count(Finding.id)).where(*filters)) or 0
    )

    if sort == FindingSortField.SEVERITY:
        order_column = severity_rank_expr(effective_severity_expr())
    elif sort == FindingSortField.TITLE:
        order_column = func.lower(Finding.title)
    elif sort == FindingSortField.LAST_SEEN_AT:
        order_column = Finding.last_seen_at
    else:
        order_column = Finding.created_at
    ordering = order_column.asc() if order == SortOrder.ASC else order_column.desc()

    rows = (
        (
            await db.execute(
                select(Finding)
                .where(*filters)
                .order_by(ordering, Finding.id.desc())
                .offset(offset)
                .limit(limit)
            )
        )
        .scalars()
        .all()
    )
    return list(rows), total


def last_updated_at(
    assessment: Assessment,
    finding_updated: datetime | None,
    scan_finished: datetime | None,
) -> datetime | None:
    candidates = [
        value
        for value in (assessment.updated_at, finding_updated, scan_finished)
        if value is not None
    ]
    return max(candidates) if candidates else None
