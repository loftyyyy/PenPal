from __future__ import annotations

from pydantic import BaseModel


class HealthResponse(BaseModel):
    status: str
    service: str
    version: str


class DependencyStatus(BaseModel):
    name: str
    ok: bool
    detail: str


class DependenciesResponse(BaseModel):
    status: str
    dependencies: list[DependencyStatus]
