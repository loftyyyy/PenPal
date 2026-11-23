"""Single aggregate query set for the assessment dashboard."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.base import utcnow
from app.db.enums import AIAnalysisStatus, AIFunction, Severity, VerificationStatus
from app.db.models import AIAnalysis, Assessment, Finding, Scan
from app.schemas.dashboard import (
    AICoverage,
    DashboardOut,
    ScanHistoryItem,
    SeverityCounts,
    TopFinding,
    VerificationCounts,
)
from app.services.findings import (
    effective_severity_expr,
    last_updated_at,
    severity_rank_expr,
)


async def build_dashboard(
    db: AsyncSession, assessment: Assessment
) -> DashboardOut:
    assessment_id = assessment.id
    total = int(
        await db.scalar(
            select(func.count(Finding.id)).where(
                Finding.assessment_id == assessment_id
            )
        )
        or 0
    )

    severity_counts = SeverityCounts()
    severity_rows = await db.execute(
        select(effective_severity_expr(), func.count(Finding.id))
        .where(Finding.assessment_id == assessment_id)
        .group_by(effective_severity_expr())
    )
    for severity, count in severity_rows.all():
        if severity is None:
            continue
        name = severity.value if isinstance(severity, Severity) else str(severity)
        if hasattr(severity_counts, name):
            setattr(severity_counts, name, int(count))

    verification_counts = VerificationCounts()
    status_rows = await db.execute(
        select(Finding.verification_status, func.count(Finding.id))
        .where(Finding.assessment_id == assessment_id)
        .group_by(Finding.verification_status)
    )
    for status, count in status_rows.all():
        name = (
            status.value
            if isinstance(status, VerificationStatus)
            else str(status)
        )
        if hasattr(verification_counts, name):
            setattr(verification_counts, name, int(count))

    category_counts = {
        (
            category.value
            if hasattr(category, "value")
            else str(category)
        ): int(count)
        for category, count in (
            await db.execute(
                select(Finding.category, func.count(Finding.id))
                .where(Finding.assessment_id == assessment_id)
                .group_by(Finding.category)
            )
        ).all()
    }

    scans = (
        (
            await db.execute(
                select(Scan)
                .where(Scan.assessment_id == assessment_id)
                .order_by(Scan.created_at.desc(), Scan.id.desc())
            )
        )
        .scalars()
        .all()
    )
    scan_history = [
        ScanHistoryItem(
            id=scan.id,
            tool=scan.tool.value,
            profile=scan.profile,
            status=scan.status.value,
            started_at=scan.started_at,
            finished_at=scan.finished_at,
            duration_seconds=scan.duration_seconds,
        )
        for scan in scans
    ]

    analyzed = int(
        await db.scalar(
            select(func.count(func.distinct(AIAnalysis.finding_id)))
            .join(Finding, Finding.id == AIAnalysis.finding_id)
            .where(
                Finding.assessment_id == assessment_id,
                AIAnalysis.function == AIFunction.INTERPRET,
                AIAnalysis.status == AIAnalysisStatus.SUCCESS,
            )
        )
        or 0
    )
    coverage = (
        round(analyzed / total * 100, 1) if total else 0.0
    )

    rank = severity_rank_expr(Finding.final_severity)
    top_rows = (
        (
            await db.execute(
                select(Finding)
                .where(
                    Finding.assessment_id == assessment_id,
                    Finding.verification_status == VerificationStatus.CONFIRMED,
                )
                .order_by(rank.desc(), Finding.last_seen_at.desc(), Finding.id.desc())
                .limit(5)
            )
        )
        .scalars()
        .all()
    )
    top_confirmed = [
        TopFinding(
            id=finding.id,
            title=finding.title,
            final_severity=(
                finding.final_severity.value if finding.final_severity else None
            ),
            category=finding.category.value,
            affected_url=finding.affected_url,
        )
        for finding in top_rows
    ]

    finding_updated: datetime | None = await db.scalar(
        select(func.max(Finding.updated_at)).where(
            Finding.assessment_id == assessment_id
        )
    )
    scan_finished: datetime | None = await db.scalar(
        select(func.max(Scan.finished_at)).where(
            Scan.assessment_id == assessment_id
        )
    )

    return DashboardOut(
        assessment_id=assessment_id,
        generated_at=utcnow(),
        total_findings=total,
        severity_counts=severity_counts,
        verification_counts=verification_counts,
        category_counts=category_counts,
        scan_history=scan_history,
        ai_coverage=AICoverage(
            analyzed=analyzed, total=total, coverage_percent=coverage
        ),
        top_confirmed_findings=top_confirmed,
        last_updated_at=last_updated_at(assessment, finding_updated, scan_finished),
    )
