"""HTTP check configuration, test accounts and scan options."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator

from app.schemas.common import ORMModel


class LoginSpec(BaseModel):
    url: str = Field(min_length=1, max_length=2048)
    method: Literal["POST"] = "POST"
    content_type: Literal["form", "json"] = "form"
    username_field: str = Field(default="username", min_length=1, max_length=100)
    password_field: str = Field(default="password", min_length=1, max_length=100)
    success_status: int | None = Field(default=200, ge=100, le=599)
    success_redirect: str | None = Field(default=None, max_length=2048)
    success_regex: str | None = Field(default=None, max_length=500)
    csrf_regex: str | None = Field(default=None, max_length=500)


class AccessRule(BaseModel):
    path: str = Field(min_length=1, max_length=2048)
    method: Literal["GET", "HEAD", "OPTIONS"] = "GET"
    allowed_roles: list[str] = Field(default_factory=list, max_length=10)
    id_template: bool = False
    sample_ids: list[str] = Field(default_factory=list, max_length=5)

    @field_validator("path")
    @classmethod
    def _path_starts_with_slash(cls, value: str) -> str:
        if not value.startswith("/"):
            raise ValueError("access rule paths must start with /")
        return value


class HttpCheckLimits(BaseModel):
    max_requests: int = Field(default=200, ge=1, le=500)
    max_rps: float = Field(default=2.0, gt=0, le=10)
    max_login_attempts: int = Field(default=5, ge=1, le=10)
    min_login_interval_seconds: float = Field(default=1.0, ge=0, le=10)
    max_redirects: int = Field(default=3, ge=0, le=3)


class HttpCheckConfigIn(BaseModel):
    login: LoginSpec | None = None
    access_rules: list[AccessRule] = Field(default_factory=list, max_length=50)
    roles: list[str] = Field(default_factory=lambda: ["staff", "admin"], max_length=10)
    limits: HttpCheckLimits = Field(default_factory=HttpCheckLimits)


class HttpCheckConfigOut(ORMModel):
    id: int
    assessment_id: int
    login: dict | None
    access_rules: list[dict]
    roles: list[str]
    limits: dict
    updated_by: int | None
    created_at: datetime
    updated_at: datetime


class TestAccountCreate(BaseModel):
    __test__ = False

    role: str = Field(min_length=1, max_length=50)
    username: str = Field(min_length=1, max_length=200)
    password: str = Field(min_length=1, max_length=200)


class TestAccountOut(ORMModel):
    id: int
    assessment_id: int
    role: str
    username: str
    created_at: datetime
