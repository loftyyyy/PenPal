from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.db.enums import ScanStatus, ScanTool


class ScanCreate(BaseModel):
    tool: ScanTool
    profile: str = Field(
        min_length=1,
        max_length=50,
        description="Nmap: quick, standard, full_tcp. ZAP: baseline, active_limited.",
    )
    target: str = Field(
        min_length=1,
        max_length=2048,
        description="Host or IP for Nmap; absolute http(s) URL for ZAP.",
    )
    ports: list[int] = Field(
        default_factory=list,
        max_length=1000,
        description="Optional Nmap ports. Empty uses the profile's default port set.",
    )


class ScanQueuedOut(BaseModel):
    scan_id: int
    status: ScanStatus


class ScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    assessment_id: int
    tool: ScanTool
    profile: str
    target: str
    status: ScanStatus
    progress: int
    started_at: datetime | None
    finished_at: datetime | None
    duration_seconds: float | None
    error: str | None
    raw_output_sha256: str | None
    has_raw_output: bool
    tool_version: str | None
    parameters: dict[str, Any]
    created_by: int
    created_at: datetime
    updated_at: datetime
