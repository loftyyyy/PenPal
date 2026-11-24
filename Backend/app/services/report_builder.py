"""Build the HTML/PDF assessment report from confirmed findings only."""

from __future__ import annotations

import asyncio
import hashlib
import logging
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.errors import AppError
from app.db.base import utcnow
from app.db.enums import (
    AIAnalysisStatus,
    ReportFormat,
    ReportStatus,
    VerificationStatus,
)
from app.db.models import AIAnalysis, Assessment, Evidence, Finding, Report, Scan, User
from app.services import audit
from app.services.findings import severity_rank_expr
from app.services.storage import resolve_data_path, write_data_file

logger = logging.getLogger(__name__)

TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"
_env = Environment(
    loader=FileSystemLoader(str(TEMPLATE_DIR)),
    # Autoescape must be explicit: the template name ends in .j2, which
    # select_autoescape() would treat as disabled.
    autoescape=True,
    trim_blocks=True,
    lstrip_blocks=True,
)
_template = _env.get_template("report.html.j2")

PdfRenderer = Callable[[str, Path], None]


@dataclass(frozen=True)
class EvidenceView:
    type: Any
    filename: str | None
    sha256: str | None
    content: str | None


def _render_pdf(html: str, path: Path) -> None:  # pragma: no cover - needs system Pango
    from weasyprint import HTML

    path.parent.mkdir(parents=True, exist_ok=True)
    HTML(string=html, base_url=str(path.parent)).write_pdf(str(path))


def _truncate(value: str | None, limit: int) -> str | None:
    if value is None:
        return None
    if len(value) <= limit:
        return value
    return value[:limit] + "\n[truncated for report]"


def _narrative(severity_counts: dict[str, int], total: int) -> str:
    if total == 0:
        return "No findings were confirmed during this assessment."
    parts = [
        f"{count} {severity}"
        for severity, count in severity_counts.items()
        if count
    ]
    highest = next(
        (severity for severity, count in severity_counts.items() if count),
        "none",
    )
    return (
        f"{total} finding(s) were confirmed by the assessor: "
        f"{', '.join(parts)}. The highest confirmed severity is {highest}. "
        "Only these confirmed findings appear in the main report; other "
        "verification outcomes appear in Appendix A."
    )


async def create_report(
    db: AsyncSession,
    assessment: Assessment,
    *,
    report_format: ReportFormat,
    user: User,
    settings: Settings,
    pdf_renderer: PdfRenderer | None = None,
) -> Report:
    report = Report(
        assessment_id=assessment.id,
        format=report_format,
        status=ReportStatus.PENDING,
        generated_by=user.id,
        summary_counts={},
    )
    db.add(report)
    await db.flush()

    try:
        context = await _build_context(db, assessment, user, settings)
        html = _template.render(**context)
        html_relative = (
            f"reports/{assessment.id}/report-{report.id}.html"
        )
        await asyncio.to_thread(
            write_data_file, settings, html_relative, html.encode("utf-8")
        )

        chosen_format = report_format
        relative_path = html_relative
        error: str | None = None
        context_summary = dict(context["summary_counts"])
        if report_format == ReportFormat.PDF:
            pdf_relative = f"reports/{assessment.id}/report-{report.id}.pdf"
            pdf_path = resolve_data_path(settings, pdf_relative)
            renderer = pdf_renderer or _render_pdf
            try:
                await asyncio.to_thread(renderer, html, pdf_path)
                if not pdf_path.is_file() or pdf_path.stat().st_size == 0:
                    raise RuntimeError("PDF renderer produced no file")
            except Exception as exc:
                logger.exception("PDF rendering failed for report %s", report.id)
                chosen_format = ReportFormat.HTML
                error = (
                    "PDF rendering failed; the HTML report is available instead "
                    f"({type(exc).__name__})"
                )
                context_summary["pdf_fallback"] = True
            else:
                relative_path = pdf_relative

        digest = hashlib.sha256(
            resolve_data_path(settings, relative_path).read_bytes()
        ).hexdigest()
        report.format = chosen_format
        report.status = ReportStatus.READY
        report.file_path = relative_path
        report.sha256 = digest
        report.summary_counts = context_summary
        report.error = error
        await audit.record(
            db,
            "report.generated",
            user_id=user.id,
            assessment_id=assessment.id,
            entity_type="report",
            entity_id=report.id,
            details={
                "requested_format": report_format.value,
                "stored_format": chosen_format.value,
                "status": report.status.value,
                "sha256": digest,
            },
        )
        await db.commit()
        await db.refresh(report)
        return report
    except Exception:  # pragma: no cover - defensive failure boundary
        logger.exception("Report generation failed for assessment %s", assessment.id)
        report.status = ReportStatus.FAILED
        report.error = "Report generation failed"
        await db.commit()
        raise AppError(
            500, "report_generation_failed", "Report generation failed"
        ) from None


async def _build_context(
    db: AsyncSession, assessment: Assessment, user: User, settings: Settings
) -> dict[str, Any]:
    confirmed = (
        (
            await db.execute(
                select(Finding)
                .where(
                    Finding.assessment_id == assessment.id,
                    Finding.verification_status == VerificationStatus.CONFIRMED,
                )
                .order_by(
                    severity_rank_expr(Finding.final_severity).desc(),
                    Finding.last_seen_at.desc(),
                    Finding.id.desc(),
                )
            )
        )
        .scalars()
        .all()
    )
    finding_ids = [finding.id for finding in confirmed]

    evidence_by_finding: dict[int, list[EvidenceView]] = defaultdict(list)
    if finding_ids:
        evidence_rows = (
            (
                await db.execute(
                    select(Evidence)
                    .where(Evidence.finding_id.in_(finding_ids))
                    .order_by(Evidence.created_at.asc(), Evidence.id.asc())
                )
            )
            .scalars()
            .all()
        )
        for evidence in evidence_rows:
            evidence_by_finding[evidence.finding_id].append(
                EvidenceView(
                    type=evidence.type,
                    filename=(
                        evidence.file_path.rsplit("/", 1)[-1]
                        if evidence.file_path
                        else None
                    ),
                    sha256=evidence.sha256,
                    content=_truncate(
                        evidence.content, settings.report_evidence_max_chars
                    ),
                )
            )

    unverified = list(
        (
            await db.execute(
                select(Finding)
                .where(
                    Finding.assessment_id == assessment.id,
                    Finding.verification_status.in_(
                        [
                            VerificationStatus.PENDING,
                            VerificationStatus.NEEDS_RETEST,
                        ]
                    ),
                )
                .order_by(Finding.id)
            )
        )
        .scalars()
        .all()
    )

    scans = (
        (
            await db.execute(
                select(Scan)
                .where(Scan.assessment_id == assessment.id)
                .order_by(Scan.created_at.asc(), Scan.id.asc())
            )
        )
        .scalars()
        .all()
    )
    version_bits = {
        f"{scan.tool.value} {scan.tool_version or ''}".strip() for scan in scans
    }
    tool_summary = ", ".join(sorted(version_bits)) if version_bits else ""

    severity_counts = {
        severity: 0 for severity in ("critical", "high", "medium", "low", "info")
    }
    for finding in confirmed:
        if finding.final_severity is not None:
            severity_counts[finding.final_severity.value] += 1

    verification_counts = {
        status.value: 0 for status in VerificationStatus
    }
    for status, count in (
        await db.execute(
            select(Finding.verification_status, func.count(Finding.id))
            .where(Finding.assessment_id == assessment.id)
            .group_by(Finding.verification_status)
        )
    ).all():
        verification_counts[status.value] = int(count)

    ai_usage = [
        {"provider": provider, "model": model, "count": int(count)}
        for provider, model, count in (
            await db.execute(
                select(
                    AIAnalysis.provider,
                    AIAnalysis.model,
                    func.count(AIAnalysis.id),
                )
                .join(Finding, Finding.id == AIAnalysis.finding_id)
                .where(
                    Finding.assessment_id == assessment.id,
                    AIAnalysis.status == AIAnalysisStatus.SUCCESS,
                )
                .group_by(AIAnalysis.provider, AIAnalysis.model)
            )
        ).all()
    ]
    redaction_summary: dict[str, int] = {}
    redaction_rows = (
        (
            await db.execute(
                select(AIAnalysis.redaction_report)
                .join(Finding, Finding.id == AIAnalysis.finding_id)
                .where(
                    Finding.assessment_id == assessment.id,
                    AIAnalysis.redaction_report.is_not(None),
                )
            )
        )
        .scalars()
        .all()
    )
    for report_json in redaction_rows:
        if not isinstance(report_json, dict):
            continue
        for kind, count in report_json.items():
            try:
                redaction_summary[kind] = redaction_summary.get(kind, 0) + int(count)
            except (TypeError, ValueError):
                continue
    redaction_summary = dict(sorted(redaction_summary.items()))

    from app.services.summaries import (
        approved_summary,
        list_summaries,
        summary_key_risks,
        summary_text,
    )

    approved = await approved_summary(db, assessment.id)
    summary_rows = await list_summaries(db, assessment.id)
    draft = next(
        (row for row in summary_rows if row.status.value == "draft"), None
    )

    scope_in = [item for item in assessment.scope_items if item.in_scope]
    scope_out = [item for item in assessment.scope_items if not item.in_scope]
    severity_rows = [
        (severity.capitalize(), severity_counts[severity])
        for severity in ("critical", "high", "medium", "low", "info")
    ]
    summary_counts = {
        "confirmed": len(confirmed),
        **severity_counts,
        "false_positive": verification_counts.get("false_positive", 0),
        "needs_retest": verification_counts.get("needs_retest", 0),
    }

    return {
        "assessment": assessment,
        "generated_at": utcnow().strftime("%Y-%m-%d %H:%M UTC"),
        "generated_by_name": user.full_name or user.email,
        "scope_in": scope_in,
        "scope_out": scope_out,
        "selected_categories": assessment.selected_categories,
        "tool_summary": tool_summary,
        "findings": confirmed,
        "unverified_findings": unverified,
        "evidence_by_finding": evidence_by_finding,
        "severity_rows": severity_rows,
        "confirmed_total": len(confirmed),
        "narrative": _narrative(severity_counts, len(confirmed)),
        "appendix_verification_rows": [
            ("False positive", verification_counts.get("false_positive", 0)),
            ("Needs retest", verification_counts.get("needs_retest", 0)),
        ],
        "ai_usage": ai_usage,
        "approved_summary": (
            {
                "text": summary_text(approved),
                "key_risks": summary_key_risks(approved),
                "overall_risk": (
                    approved.overall_risk.value
                    if approved.overall_risk
                    else None
                ),
            }
            if approved
            else None
        ),
        "draft_summary": (
            {
                "text": summary_text(draft),
                "key_risks": summary_key_risks(draft),
            }
            if draft
            else None
        ),
        "redaction_summary": redaction_summary,
        "scan_history": scans,
        "summary_counts": summary_counts,
    }


async def list_reports(
    db: AsyncSession, assessment_id: int, *, offset: int, limit: int
) -> tuple[list[Report], int]:
    total = int(
        await db.scalar(
            select(func.count(Report.id)).where(
                Report.assessment_id == assessment_id
            )
        )
        or 0
    )
    rows = (
        (
            await db.execute(
                select(Report)
                .where(Report.assessment_id == assessment_id)
                .order_by(Report.created_at.desc(), Report.id.desc())
                .offset(offset)
                .limit(limit)
            )
        )
        .scalars()
        .all()
    )
    return list(rows), total


async def get_report(db: AsyncSession, report_id: int) -> Report | None:
    return await db.get(Report, report_id)


__all__ = [
    "EvidenceView",
    "create_report",
    "get_report",
    "list_reports",
]
