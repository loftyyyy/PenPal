"""Report request and response models."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict

from app.db.enums import ReportFormat, ReportStatus


class ReportCreate(BaseModel):
    format: ReportFormat


class ReportOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    assessment_id: int
    format: ReportFormat
    status: ReportStatus
    sha256: str | None
    generated_by: int
    summary_counts: dict[str, Any]
    error: str | None
    has_file: bool
    created_at: datetime
    updated_at: datetime
