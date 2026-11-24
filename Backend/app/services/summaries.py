"""Assessment summary workflow: draft, edit, approve."""

from __future__ import annotations

import json

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import AppError, NotFoundError
from app.db.base import utcnow
from app.db.enums import SEVERITY_ORDER, Severity, SummaryStatus, VerificationStatus
from app.db.models import Assessment, AssessmentSummary, Finding, User
from app.schemas.summary import SummaryEdit
from app.services import audit
from app.services.ai.service import AIAnalysisService

NO_CONFIRMED_SUMMARY = (
    "No findings were confirmed during this assessment. Unverified tool output and AI "
    "suggestions remain in the assessment record but are not presented as vulnerabilities."
)


def overall_risk_for(findings: list[Finding]) -> Severity:
    highest = Severity.INFO
    for finding in findings:
        if (
            finding.final_severity is not None
            and SEVERITY_ORDER[finding.final_severity] > SEVERITY_ORDER[highest]
        ):
            highest = finding.final_severity
    return highest


async def _confirmed(db: AsyncSession, assessment_id: int) -> list[Finding]:
    return list(
        (
            await db.execute(
                select(Finding).where(
                    Finding.assessment_id == assessment_id,
                    Finding.verification_status == VerificationStatus.CONFIRMED,
                )
            )
        )
        .scalars()
        .all()
    )


async def generate_summary(
    db: AsyncSession,
    assessment: Assessment,
    user: User,
    ai_service: AIAnalysisService,
) -> AssessmentSummary:
    confirmed = await _confirmed(db, assessment.id)
    overall_risk = overall_risk_for(confirmed)
    if not confirmed:
        output = {
            "executive_summary": NO_CONFIRMED_SUMMARY,
            "key_risks": [],
            "limitations_note": (
                "Deterministic server summary: the AI was not called because there "
                "were no confirmed findings."
            ),
        }
        summary = AssessmentSummary(
            assessment_id=assessment.id,
            status=SummaryStatus.DRAFT,
            generated_by=user.id,
            provider="deterministic",
            model="rules",
            sanitized_input=json.dumps(
                {
                    "confirmed_counts": {
                        "by_severity": {severity.value: 0 for severity in SEVERITY_ORDER},
                        "total": 0,
                    }
                },
                sort_keys=True,
            ),
            output=output,
            overall_risk=overall_risk,
        )
        db.add(summary)
        await db.flush()
        await audit.record(
            db,
            "summary.generated",
            user_id=user.id,
            assessment_id=assessment.id,
            entity_type="summary",
            entity_id=summary.id,
            details={"provider": summary.provider, "model": summary.model},
        )
        await db.commit()
        await db.refresh(summary)
        return summary

    analysis = await ai_service.analyze_assessment_summary(
        db, assessment, user_id=user.id
    )
    if analysis.status.value != "success" or not isinstance(analysis.output, dict):
        raise AppError(
            502,
            "summary_generation_failed",
            "AI summary generation failed; the attempt is stored in ai_analyses",
        )
    summary = AssessmentSummary(
        assessment_id=assessment.id,
        status=SummaryStatus.DRAFT,
        generated_by=user.id,
        provider=analysis.provider,
        model=analysis.model,
        sanitized_input=analysis.sanitized_input,
        output=analysis.output,
        overall_risk=overall_risk,
        ai_analysis_id=analysis.id,
    )
    db.add(summary)
    await db.flush()
    await audit.record(
        db,
        "summary.generated",
        user_id=user.id,
        assessment_id=assessment.id,
        entity_type="summary",
        entity_id=summary.id,
        details={"provider": summary.provider, "model": summary.model},
    )
    await db.commit()
    await db.refresh(summary)
    return summary


async def list_summaries(
    db: AsyncSession, assessment_id: int
) -> list[AssessmentSummary]:
    return list(
        (
            await db.execute(
                select(AssessmentSummary)
                .where(AssessmentSummary.assessment_id == assessment_id)
                .order_by(AssessmentSummary.id.desc())
            )
        )
        .scalars()
        .all()
    )


async def get_summary(db: AsyncSession, summary_id: int) -> AssessmentSummary:
    summary = await db.get(AssessmentSummary, summary_id)
    if summary is None:
        raise NotFoundError("Summary", summary_id)
    return summary


async def edit_summary(
    db: AsyncSession, summary: AssessmentSummary, payload: SummaryEdit, user: User
) -> AssessmentSummary:
    summary.edited_text = payload.text.strip()
    if summary.status == SummaryStatus.APPROVED:
        summary.status = SummaryStatus.DRAFT
        summary.approved_by = None
        summary.approved_at = None
    await audit.record(
        db,
        "summary.edited",
        user_id=user.id,
        assessment_id=summary.assessment_id,
        entity_type="summary",
        entity_id=summary.id,
        details={"text_length": len(summary.edited_text or "")},
    )
    await db.commit()
    await db.refresh(summary)
    return summary


async def approve_summary(
    db: AsyncSession, summary: AssessmentSummary, user: User
) -> AssessmentSummary:
    previous = (
        (
            await db.execute(
                select(AssessmentSummary).where(
                    AssessmentSummary.assessment_id == summary.assessment_id,
                    AssessmentSummary.status == SummaryStatus.APPROVED,
                )
            )
        )
        .scalars()
        .all()
    )
    for row in previous:
        if row.id != summary.id:
            row.status = SummaryStatus.SUPERSEDED
    summary.status = SummaryStatus.APPROVED
    summary.approved_by = user.id
    summary.approved_at = utcnow()
    await audit.record(
        db,
        "summary.approved",
        user_id=user.id,
        assessment_id=summary.assessment_id,
        entity_type="summary",
        entity_id=summary.id,
        details={"superseded": [row.id for row in previous if row.id != summary.id]},
    )
    await db.commit()
    await db.refresh(summary)
    return summary


async def approved_summary(
    db: AsyncSession, assessment_id: int
) -> AssessmentSummary | None:
    return await db.scalar(
        select(AssessmentSummary)
        .where(
            AssessmentSummary.assessment_id == assessment_id,
            AssessmentSummary.status == SummaryStatus.APPROVED,
        )
        .order_by(AssessmentSummary.id.desc())
        .limit(1)
    )


def summary_text(summary: AssessmentSummary) -> str:
    if summary.edited_text:
        return summary.edited_text
    if isinstance(summary.output, dict):
        value = summary.output.get("executive_summary")
        if isinstance(value, str):
            return value
    return NO_CONFIRMED_SUMMARY


def summary_key_risks(summary: AssessmentSummary) -> list[str]:
    if isinstance(summary.output, dict):
        values = summary.output.get("key_risks")
        if isinstance(values, list):
            return [str(value) for value in values]
    return []


__all__ = [
    "NO_CONFIRMED_SUMMARY",
    "approve_summary",
    "approved_summary",
    "edit_summary",
    "generate_summary",
    "get_summary",
    "list_summaries",
    "overall_risk_for",
    "summary_key_risks",
    "summary_text",
]
