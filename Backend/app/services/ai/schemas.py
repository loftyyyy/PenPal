"""Strict output schemas for the AI functions."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from app.db.enums import AIConfidence, RemediationEffort, Severity


class InterpretOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    plain_language_explanation: str = Field(min_length=1, max_length=4000)
    why_it_matters: str = Field(min_length=1, max_length=4000)
    suggested_severity: Severity
    severity_rationale: str = Field(min_length=1, max_length=2000)
    likely_false_positive: bool
    confidence: AIConfidence
    owasp_category: str | None = Field(default=None, max_length=100)
    verification_hints: list[str] = Field(min_length=1, max_length=10)


class RemediateOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    summary: str = Field(min_length=1, max_length=2000)
    steps: list[str] = Field(min_length=1, max_length=20)
    code_or_config_example: str | None = Field(default=None, max_length=8000)
    references: list[str] = Field(default_factory=list, max_length=20)
    effort: RemediationEffort


class SummaryOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    executive_summary: str = Field(min_length=1, max_length=6000)
    key_risks: list[str] = Field(min_length=1, max_length=10)
    limitations_note: str | None = Field(default=None, max_length=2000)
