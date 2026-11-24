"""Finding, verification and evidence request/response models."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.db.enums import (
    EvidenceType,
    FindingCategory,
    FindingSource,
    Severity,
    VerificationDecision,
    VerificationStatus,
)


class FindingSortField(StrEnum):
    CREATED_AT = "created_at"
    LAST_SEEN_AT = "last_seen_at"
    SEVERITY = "severity"
    TITLE = "title"


class SortOrder(StrEnum):
    ASC = "asc"
    DESC = "desc"


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    assessment_id: int
    scan_id: int | None
    source: FindingSource
    title: str
    description: str | None
    category: FindingCategory
    owasp_category: str | None
    cwe: str | None
    affected_url: str | None
    http_method: str | None
    parameter: str | None
    tool_severity: Severity | None
    ai_suggested_severity: Severity | None
    final_severity: Severity | None
    likelihood: int | None
    impact: int | None
    tool_confidence: str | None
    verification_status: VerificationStatus
    rejection_reason: str | None
    verified_by: int | None
    verified_at: datetime | None
    final_remediation: str | None
    first_seen_at: datetime
    last_seen_at: datetime
    seen_count: int
    created_at: datetime
    updated_at: datetime


class FindingDetailOut(FindingOut):
    raw: dict[str, Any]


class ManualFindingCreate(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "title": "Business logic bypass in checkout",
                "description": "A negative quantity increases store credit.",
                "category": "business_logic",
                "severity": "high",
                "affected_url": "http://target:3000/checkout",
                "http_method": "POST",
                "parameter": "quantity",
                "cwe": "CWE-840",
            }
        }
    )

    title: str = Field(min_length=1, max_length=500)
    description: str | None = Field(default=None, max_length=10_000)
    category: FindingCategory = FindingCategory.UNCATEGORIZED
    severity: Severity
    affected_url: str | None = Field(default=None, max_length=2048)
    http_method: str | None = Field(default=None, max_length=20)
    parameter: str | None = Field(default=None, max_length=200)
    cwe: str | None = Field(default=None, max_length=50)
    owasp_category: str | None = Field(default=None, max_length=100)


class FindingVerify(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "decision": "confirmed",
                "final_severity": "high",
                "likelihood": 4,
                "impact": 4,
                "final_remediation": "Use parameterised queries.",
                "reason": None,
            }
        }
    )

    decision: VerificationDecision
    final_severity: Severity | None = None
    likelihood: int | None = Field(
        default=None,
        ge=1,
        le=5,
        description="Likelihood 1 (rare) to 5 (almost certain).",
    )
    impact: int | None = Field(
        default=None,
        ge=1,
        le=5,
        description="Impact 1 (negligible) to 5 (severe).",
    )
    final_remediation: str | None = Field(default=None, max_length=20_000)
    reason: str | None = Field(default=None, max_length=5000)


class EvidenceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    finding_id: int | None
    scan_id: int | None
    type: EvidenceType
    content: str | None
    filename: str | None = None
    sha256: str | None
    created_by: int | None
    created_at: datetime

    @classmethod
    def from_evidence(cls, evidence: Any) -> EvidenceOut:
        filename = None
        if evidence.file_path:
            filename = evidence.file_path.rsplit("/", 1)[-1]
        return cls(
            id=evidence.id,
            finding_id=evidence.finding_id,
            scan_id=evidence.scan_id,
            type=evidence.type,
            content=evidence.content,
            filename=filename,
            sha256=evidence.sha256,
            created_by=evidence.created_by,
            created_at=evidence.created_at,
        )
