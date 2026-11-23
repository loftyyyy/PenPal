from __future__ import annotations

from datetime import datetime
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.db.enums import AssessmentStatus, FindingCategory, ScanTool, ScopeKind


class AssessmentCreate(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "name": "LSRS assessment",
                "target_name": "Love & Styles Rental System",
                "target_base_url": "http://target:3000",
                "owner_name": "LSRS owners",
                "authorization_reference": "signed-authorization-letter.pdf",
                "hosting_environment": "Docker Compose internal network",
                "selected_categories": ["injection", "access_control"],
            }
        }
    )

    name: str = Field(min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=5000)
    target_name: str = Field(min_length=1, max_length=200)
    target_base_url: str | None = Field(default=None, max_length=2048)
    target_description: str | None = Field(default=None, max_length=5000)
    owner_name: str = Field(min_length=1, max_length=200)
    authorization_reference: str = Field(min_length=1, max_length=5000)
    hosting_environment: str | None = Field(default=None, max_length=200)
    selected_categories: list[FindingCategory] = Field(default_factory=list)

    @field_validator("target_base_url")
    @classmethod
    def _validate_target_url(cls, value: str | None) -> str | None:
        if value is None:
            return None
        text = value.strip()
        parts = urlsplit(text)
        if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
            raise ValueError("target_base_url must be an absolute http(s) URL")
        if parts.username is not None or parts.password is not None:
            raise ValueError("target_base_url must not contain userinfo")
        return text

    @field_validator("selected_categories")
    @classmethod
    def _unique_categories(cls, value: list[FindingCategory]) -> list[FindingCategory]:
        return list(dict.fromkeys(value))


class AssessmentUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=5000)
    target_name: str | None = Field(default=None, min_length=1, max_length=200)
    target_base_url: str | None = Field(default=None, max_length=2048)
    target_description: str | None = Field(default=None, max_length=5000)
    owner_name: str | None = Field(default=None, min_length=1, max_length=200)
    authorization_reference: str | None = Field(default=None, min_length=1, max_length=5000)
    hosting_environment: str | None = Field(default=None, max_length=200)
    selected_categories: list[FindingCategory] | None = None
    status: AssessmentStatus | None = None

    @field_validator("target_base_url")
    @classmethod
    def _validate_target_url(cls, value: str | None) -> str | None:
        return AssessmentCreate._validate_target_url(value)

    @field_validator("selected_categories")
    @classmethod
    def _unique_categories(
        cls, value: list[FindingCategory] | None
    ) -> list[FindingCategory] | None:
        if value is None:
            return None
        return list(dict.fromkeys(value))


class AssessmentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    description: str | None
    target_name: str
    target_base_url: str | None
    target_description: str | None
    owner_name: str
    authorization_reference: str
    authorization_confirmed: bool
    authorization_confirmed_by: int | None
    authorization_confirmed_at: datetime | None
    hosting_environment: str | None
    selected_categories: list[str]
    status: AssessmentStatus
    created_by: int
    created_at: datetime
    updated_at: datetime


class ConfirmAuthorizationRequest(BaseModel):
    note: str | None = Field(default=None, max_length=2000)


class ScopeItemCreate(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {"kind": "host", "value": "target", "in_scope": True}
        }
    )

    kind: ScopeKind
    value: str = Field(min_length=1, max_length=2048)
    in_scope: bool = True
    note: str | None = Field(default=None, max_length=500)


class ScopeItemOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    assessment_id: int
    kind: ScopeKind
    value: str
    in_scope: bool
    note: str | None
    created_at: datetime
    updated_at: datetime


class ScopeCheckRequest(BaseModel):
    target: str = Field(min_length=1, max_length=2048)
    tool: ScanTool
    ports: list[int] = Field(default_factory=list, max_length=1000)


class ScopeCheckResponse(BaseModel):
    allowed: bool
    reasons: list[str]
    target: dict[str, object] | None = None
    resolved_ips: list[str] = Field(default_factory=list)
    matched_rules: list[str] = Field(default_factory=list)
    zap_context_include: list[str] = Field(default_factory=list)
    zap_context_exclude: list[str] = Field(default_factory=list)
