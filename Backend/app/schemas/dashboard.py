"""Dashboard response models."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from app.schemas.summary import SummaryOut


class SeverityCounts(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class VerificationCounts(BaseModel):
    pending: int = 0
    confirmed: int = 0
    false_positive: int = 0
    needs_retest: int = 0


class UnverifiedSeverityCounts(BaseModel):
    ai: SeverityCounts = Field(default_factory=SeverityCounts)
    tool: SeverityCounts = Field(default_factory=SeverityCounts)
    total: SeverityCounts = Field(default_factory=SeverityCounts)


class CategoryCounts(BaseModel):
    confirmed: dict[str, int] = Field(default_factory=dict)
    unverified: dict[str, int] = Field(default_factory=dict)


class ScanHistoryItem(BaseModel):
    id: int
    tool: str
    profile: str
    status: str
    started_at: datetime | None
    finished_at: datetime | None
    duration_seconds: float | None


class AICoverage(BaseModel):
    analyzed: int = 0
    total: int = 0
    coverage_percent: float = 0.0


class TopFinding(BaseModel):
    id: int
    title: str
    final_severity: str | None
    category: str
    affected_url: str | None


class DashboardOut(BaseModel):
    assessment_id: int
    generated_at: datetime
    total_findings: int
    severity_confirmed: SeverityCounts
    severity_unverified: UnverifiedSeverityCounts
    severity_basis: str = Field(
        default=(
            "Confirmed findings use the server-computed final severity. Unverified "
            "findings are shown separately using AI-suggested severity when present, "
            "otherwise tool severity. False positives are excluded from severity "
            "counts."
        ),
        description=(
            "Confirmed findings use the server-computed final severity. Unverified "
            "findings are shown separately using AI-suggested severity when present, "
            "otherwise tool severity. False positives are excluded from severity "
            "counts."
        ),
    )
    status_counts: VerificationCounts
    category_counts: CategoryCounts
    scan_history: list[ScanHistoryItem]
    ai_coverage: AICoverage
    ai_summary: SummaryOut | None = None
    top_confirmed_findings: list[TopFinding]
    last_updated_at: datetime | None
