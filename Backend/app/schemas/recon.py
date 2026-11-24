from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


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


class ReconDNSOut(BaseModel):
    scan_id: int
    target: str
    records: dict[str, list[str]]
    record_count: int


class ReconWhoisOut(BaseModel):
    scan_id: int
    target: str
    skipped: bool
    note: str | None = None
    fields: dict[str, str]


class ReconTechnologyOut(BaseModel):
    scan_id: int
    target: str
    status_code: int | None = None
    targets: list[str]
    technologies: dict[str, list[str]]


class ReconHTTPOut(BaseModel):
    scan_id: int
    target: str
    status_code: int | None = None
    content_type: str | None = None
    header_count: int = 0
    body_bytes: int = 0
    location: str | None = None


class ReconOut(BaseModel):
    assessment_id: int
    generated_at: datetime
    totals: ReconTotalsOut
    scans: list[ReconScanOut]
    hosts: list[ReconHostOut]
    dns: list[ReconDNSOut] = Field(default_factory=list)
    whois: list[ReconWhoisOut] = Field(default_factory=list)
    technologies: list[ReconTechnologyOut] = Field(default_factory=list)
    http: list[ReconHTTPOut] = Field(default_factory=list)
