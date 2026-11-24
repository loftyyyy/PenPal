"""Human verification rules. AI never touches these fields."""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import AppError
from app.db.base import utcnow
from app.db.enums import (
    AIAnalysisStatus,
    AIFunction,
    VerificationDecision,
    VerificationStatus,
)
from app.db.models import AIAnalysis, Finding, User
from app.schemas.findings import FindingVerify
from app.services import audit
from app.services.severity import severity_for_risk, validate_scale

MIN_REJECTION_REASON = 10


def _state(finding: Finding) -> dict[str, Any]:
    return {
        "verification_status": finding.verification_status.value,
        "final_severity": (
            finding.final_severity.value if finding.final_severity else None
        ),
        "likelihood": finding.likelihood,
        "impact": finding.impact,
        "final_remediation": finding.final_remediation,
        "rejection_reason": finding.rejection_reason,
    }


def _invalid(message: str) -> AppError:
    return AppError(422, "invalid_verification", message)


async def verify_finding(
    db: AsyncSession,
    finding: Finding,
    payload: FindingVerify,
    user: User,
) -> Finding:
    previous = _state(finding)
    decision = payload.decision
    reason = (payload.reason or "").strip()
    if payload.final_severity is not None:
        raise _invalid(
            "final_severity is read-only; the server computes it from likelihood and "
            "impact"
        )
    likelihood = validate_scale("likelihood", payload.likelihood)
    impact = validate_scale("impact", payload.impact)
    matrix_severity = (
        severity_for_risk(likelihood, impact)
        if likelihood is not None and impact is not None
        else None
    )
    accepted_ai_remediation = False

    if decision == VerificationDecision.FALSE_POSITIVE:
        if len(reason) < MIN_REJECTION_REASON:
            raise _invalid(
                "A false-positive decision needs a reason of at least "
                f"{MIN_REJECTION_REASON} characters"
            )
        finding.verification_status = VerificationStatus.FALSE_POSITIVE
        finding.rejection_reason = reason
        finding.final_severity = None
        finding.final_remediation = None
        finding.likelihood = None
        finding.impact = None
    elif decision == VerificationDecision.CONFIRMED:
        if likelihood is None or impact is None or matrix_severity is None:
            raise _invalid(
                "A confirmed finding requires likelihood and impact (1-5)"
            )
        final_remediation = (payload.final_remediation or "").strip() or None
        if final_remediation is None:
            ai_remediation = await db.scalar(
                select(AIAnalysis)
                .where(
                    AIAnalysis.finding_id == finding.id,
                    AIAnalysis.function == AIFunction.REMEDIATE,
                    AIAnalysis.status == AIAnalysisStatus.SUCCESS,
                )
                .order_by(AIAnalysis.id.desc())
                .limit(1)
            )
            if ai_remediation is not None and isinstance(
                ai_remediation.output, dict
            ):
                candidate = ai_remediation.output.get("summary")
                if not candidate:
                    try:
                        candidate = "\n".join(
                            str(step)
                            for step in ai_remediation.output.get("steps", [])
                        )
                    except TypeError:
                        candidate = None
                final_remediation = str(candidate).strip() if candidate else None
                accepted_ai_remediation = final_remediation is not None
        if final_remediation is None:
            raise _invalid(
                "A confirmed finding needs final_remediation or an existing AI "
                "remediation to accept"
            )
        finding.verification_status = VerificationStatus.CONFIRMED
        finding.final_severity = matrix_severity
        finding.final_remediation = final_remediation
        finding.rejection_reason = None
        finding.likelihood = likelihood
        finding.impact = impact
    else:
        finding.verification_status = VerificationStatus.NEEDS_RETEST
        finding.final_severity = matrix_severity
        finding.final_remediation = (
            (payload.final_remediation or "").strip() or None
        )
        finding.rejection_reason = reason or None
        finding.likelihood = likelihood
        finding.impact = impact

    finding.verified_by = user.id
    finding.verified_at = utcnow()
    await db.flush()
    await audit.record(
        db,
        "finding.verified",
        user_id=user.id,
        assessment_id=finding.assessment_id,
        entity_type="finding",
        entity_id=finding.id,
        details={
            "decision": decision.value,
            "previous": previous,
            "new": _state(finding),
            "severity_source": "matrix" if matrix_severity is not None else "none",
            "accepted_ai_remediation": accepted_ai_remediation,
        },
    )
    await db.commit()
    await db.refresh(finding)
    return finding
