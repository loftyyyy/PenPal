from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel


class ReconServiceOut(BaseModel):
    name: str | None = None
    product: str | None = None
    version: str | None = None
    extrainfo: str | None = None
    tunnel: str | None = None


class ReconPortOut(BaseModel):
    port: int
    protocol: str
    state: str
    reason: str | None = None
    service: ReconServiceOut | None = None


class ReconHostOut(BaseModel):
    address: str
    address_type: str
    status: str
    hostnames: list[str]
    os_matches: list[str]
    ports: list[ReconPortOut]
    scan_ids: list[int]


class ReconScanOut(BaseModel):
    id: int
    profile: str
    target: str
    status: str
    progress: int
    started_at: datetime | None
    finished_at: datetime | None
    duration_seconds: float | None
    tool_version: str | None
    raw_output_sha256: str | None
    error: str | None
    parse_error: str | None = None


class ReconTotalsOut(BaseModel):
    scans: int
    hosts: int
    hosts_up: int
    open_ports: int


class ReconOut(BaseModel):
    assessment_id: int
    generated_at: datetime
    totals: ReconTotalsOut
    scans: list[ReconScanOut]
    hosts: list[ReconHostOut]
