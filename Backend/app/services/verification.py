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

MIN_REJECTION_REASON = 10


def _state(finding: Finding) -> dict[str, Any]:
    return {
        "verification_status": finding.verification_status.value,
        "final_severity": (
            finding.final_severity.value if finding.final_severity else None
        ),
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
    severity_defaulted = False

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
    elif decision == VerificationDecision.CONFIRMED:
        final_severity = (
            payload.final_severity
            or finding.ai_suggested_severity
            or finding.tool_severity
        )
        if final_severity is None:
            raise _invalid(
                "A confirmed finding needs final_severity, or an AI/tool severity to "
                "fall back to"
            )
        severity_defaulted = payload.final_severity is None
        finding.verification_status = VerificationStatus.CONFIRMED
        finding.final_severity = Severity(final_severity)
        finding.final_remediation = payload.final_remediation
        finding.rejection_reason = None
    else:
        finding.verification_status = VerificationStatus.NEEDS_RETEST
        finding.final_severity = payload.final_severity
        finding.final_remediation = payload.final_remediation
        finding.rejection_reason = reason or None

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
        },
    )
    await db.commit()
    await db.refresh(finding)
    return finding
