"""Assessment summary API models."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from app.db.enums import Severity, SummaryStatus


class SummaryOut(BaseModel):
    id: int
    assessment_id: int
    status: SummaryStatus
    provider: str
    model: str
    output: dict[str, Any] | None
    edited_text: str | None
    text: str
    overall_risk: Severity | None
    approved_by: int | None
    approved_at: datetime | None
    created_at: datetime
    updated_at: datetime


class SummaryBundle(BaseModel):
    latest: SummaryOut | None
    history: list[SummaryOut]


class SummaryEdit(BaseModel):
    text: str = Field(min_length=1, max_length=6000)
