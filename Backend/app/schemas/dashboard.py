"""Dashboard response models."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


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
    severity_counts: SeverityCounts
    severity_basis: str = Field(
        default=(
            "Confirmed findings use final severity; other findings use AI-suggested "
            "severity when present, otherwise tool severity."
        ),
        description=(
            "Confirmed findings use final severity; other findings use AI-suggested "
            "severity when present, otherwise tool severity."
        ),
    )
    verification_counts: VerificationCounts
    category_counts: dict[str, int]
    scan_history: list[ScanHistoryItem]
    ai_coverage: AICoverage
    top_confirmed_findings: list[TopFinding]
    last_updated_at: datetime | None
