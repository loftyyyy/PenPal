from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.db.enums import ScanStatus, ScanTool


class ScanCreate(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "tool": "zap",
                "profile": "baseline",
                "target": "http://target:3000/",
                "ports": [],
            }
        }
    )

    tool: ScanTool
    profile: str = Field(
        min_length=1,
        max_length=50,
        description=(
            "Nmap: quick, standard, full_tcp. ZAP: baseline, active_limited. "
            "dig, whois, whatweb and curl: default."
        ),
    )
    target: str = Field(
        min_length=1,
        max_length=2048,
        description=(
            "Host or IP for Nmap, dig and whois; absolute http(s) URL for ZAP, "
            "whatweb and curl."
        ),
    )
    ports: list[int] = Field(
        default_factory=list,
        max_length=1000,
        description="Optional Nmap ports. Empty uses the profile's default port set.",
    )
    confirm_lockout_test: bool = Field(
        default=False,
        description=(
            "Only for http_checks auth_limited: explicitly allow a short lockout test "
            "against configured test accounts."
        ),
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
