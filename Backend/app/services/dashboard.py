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
    CategoryCounts,
    DashboardOut,
    ScanHistoryItem,
    SeverityCounts,
    TopFinding,
    UnverifiedSeverityCounts,
    VerificationCounts,
)
from app.services.findings import last_updated_at, severity_rank_expr


def _add_severity(counts: SeverityCounts, severity: object, amount: int) -> None:
    if severity is None:
        return
    name = severity.value if isinstance(severity, Severity) else str(severity)
    if hasattr(counts, name):
        setattr(counts, name, getattr(counts, name) + amount)


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

    severity_confirmed = SeverityCounts()
    severity_rows = await db.execute(
        select(Finding.final_severity, func.count(Finding.id))
        .where(
            Finding.assessment_id == assessment_id,
            Finding.verification_status == VerificationStatus.CONFIRMED,
        )
        .group_by(Finding.final_severity)
    )
    for severity, count in severity_rows.all():
        _add_severity(severity_confirmed, severity, int(count))

    status_counts = VerificationCounts()
    status_rows = await db.execute(
        select(Finding.verification_status, func.count(Finding.id))
        .where(Finding.assessment_id == assessment_id)
        .group_by(Finding.verification_status)
    )
    for status, count in status_rows.all():
        name = (
            status.value if isinstance(status, VerificationStatus) else str(status)
        )
        if hasattr(status_counts, name):
            setattr(status_counts, name, int(count))

    unverified = UnverifiedSeverityCounts()
    category_counts = CategoryCounts()
    category_rows = await db.execute(
        select(
            Finding.category,
            Finding.verification_status,
            Finding.ai_suggested_severity,
            Finding.tool_severity,
            func.count(Finding.id),
        )
        .where(Finding.assessment_id == assessment_id)
        .group_by(
            Finding.category,
            Finding.verification_status,
            Finding.ai_suggested_severity,
            Finding.tool_severity,
        )
    )
    for category, status, ai_severity, tool_severity, count in category_rows.all():
        category_name = (
            category.value if hasattr(category, "value") else str(category)
        )
        if status == VerificationStatus.CONFIRMED:
            category_counts.confirmed[category_name] = (
                category_counts.confirmed.get(category_name, 0) + int(count)
            )
            continue
        if status == VerificationStatus.FALSE_POSITIVE:
            continue
        category_counts.unverified[category_name] = (
            category_counts.unverified.get(category_name, 0) + int(count)
        )
        if ai_severity is not None:
            _add_severity(unverified.ai, ai_severity, int(count))
        else:
            _add_severity(unverified.tool, tool_severity, int(count))
        if ai_severity is not None:
            _add_severity(unverified.total, ai_severity, int(count))
        else:
            _add_severity(unverified.total, tool_severity, int(count))

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

    from app.services.summaries import approved_summary, summary_text

    summary = await approved_summary(db, assessment_id)

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
        severity_confirmed=severity_confirmed,
        severity_unverified=unverified,
        status_counts=status_counts,
        category_counts=category_counts,
        scan_history=scan_history,
        ai_coverage=AICoverage(
            analyzed=analyzed, total=total, coverage_percent=coverage
        ),
        ai_summary=(
            {
                "id": summary.id,
                "assessment_id": summary.assessment_id,
                "status": summary.status,
                "provider": summary.provider,
                "model": summary.model,
                "output": summary.output,
                "edited_text": summary.edited_text,
                "text": summary_text(summary),
                "overall_risk": summary.overall_risk,
                "approved_by": summary.approved_by,
                "approved_at": summary.approved_at,
                "created_at": summary.created_at,
                "updated_at": summary.updated_at,
            }
            if summary
            else None
        ),
        top_confirmed_findings=top_confirmed,
        last_updated_at=last_updated_at(assessment, finding_updated, scan_finished),
    )
