"""API models for advisory AI analysis."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.db.enums import AIAnalysisStatus, AIFunction, Severity
from app.services.ai.manager import AIJob, AIJobStatus


class AIAnalysisOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    finding_id: int | None
    assessment_id: int | None
    function: AIFunction
    provider: str
    model: str
    prompt_version: str
    input_hash: str
    sanitized_input: str
    output: dict[str, Any] | None
    status: AIAnalysisStatus
    error: str | None
    latency_ms: int | None
    prompt_tokens: int | None
    completion_tokens: int | None
    redaction_report: dict[str, Any] | None
    attempts: list[dict[str, Any]] | None = None
    created_at: datetime


class FindingAnalysisOut(BaseModel):
    finding_id: int
    analyses: list[AIAnalysisOut]


class BulkAnalyzeRequest(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {"min_severity": "medium", "only_unanalyzed": True}
        }
    )

    min_severity: Severity | None = Field(
        default=None,
        description="Only analyze findings at or above this severity.",
    )
    only_unanalyzed: bool = Field(
        default=True,
        description="Skip findings that already have a successful interpretation.",
    )
    force: bool = Field(
        default=False,
        description="Bypass the AI cache and regenerate analyses.",
    )


class BulkAnalyzeQueued(BaseModel):
    job_id: int
    assessment_id: int
    status: AIJobStatus
    total: int


class AIJobOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    assessment_id: int
    status: AIJobStatus
    total: int
    processed: int
    failed: int
    error: str | None
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None

    @classmethod
    def from_job(cls, job: AIJob) -> AIJobOut:
        return cls.model_validate(job, from_attributes=True)


class AIStatusOut(BaseModel):
    assessment_id: int
    total_findings: int
    findings_with_interpretation: int
    findings_with_remediation: int
    pending_findings: int
    last_analyzed_at: datetime | None
    job: AIJobOut | None
