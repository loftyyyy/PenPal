"""Human verification rules. AI never touches these fields."""

from __future__ import annotations

from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import AppError
from app.db.base import utcnow
from app.db.enums import Severity, VerificationDecision, VerificationStatus
from app.db.models import Finding, User
from app.schemas.findings import FindingVerify
from app.services import audit
from app.services.risk_matrix import severity_for_risk, validate_scale

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
    likelihood = validate_scale("likelihood", payload.likelihood)
    impact = validate_scale("impact", payload.impact)
    if (likelihood is None) != (impact is None):
        raise _invalid("Provide both likelihood and impact, or neither")
    matrix_severity = (
        severity_for_risk(likelihood, impact)
        if likelihood is not None and impact is not None
        else None
    )

    severity_defaulted = False
    severity_source: str | None = None

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
        finding.likelihood = likelihood
        finding.impact = impact
        severity_source = "none"
    elif decision == VerificationDecision.CONFIRMED:
        if payload.final_severity is not None:
            final_severity = payload.final_severity
            severity_source = "assessor"
        elif matrix_severity is not None:
            final_severity = matrix_severity
            severity_source = "matrix"
        elif finding.ai_suggested_severity is not None:
            final_severity = finding.ai_suggested_severity
            severity_source = "ai"
            severity_defaulted = True
        elif finding.tool_severity is not None:
            final_severity = finding.tool_severity
            severity_source = "tool"
            severity_defaulted = True
        else:
            raise _invalid(
                "A confirmed finding needs final_severity, a likelihood/impact pair, "
                "or an AI/tool severity to fall back to"
            )
        finding.verification_status = VerificationStatus.CONFIRMED
        finding.final_severity = Severity(final_severity)
        finding.final_remediation = payload.final_remediation
        finding.rejection_reason = None
        finding.likelihood = likelihood
        finding.impact = impact
    else:
        finding.verification_status = VerificationStatus.NEEDS_RETEST
        if payload.final_severity is not None:
            finding.final_severity = payload.final_severity
            severity_source = "assessor"
        elif matrix_severity is not None:
            finding.final_severity = matrix_severity
            severity_source = "matrix"
        else:
            finding.final_severity = None
            severity_source = "none"
        finding.final_remediation = payload.final_remediation
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
            "severity_defaulted": severity_defaulted,
            "severity_source": severity_source,
        },
    )
    await db.commit()
    await db.refresh(finding)
    return finding
