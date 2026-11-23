from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.db.enums import Role
from app.schemas.common import EmailAddress


class LoginRequest(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "email": "admin@penpal.local",
                "password": "replace-with-a-real-password",
            }
        }
    )

    email: EmailAddress
    password: str = Field(min_length=1, max_length=200)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"  # noqa: S105
    expires_in: int
    user: UserSummary


class UserSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    email: EmailAddress
    full_name: str
    role: Role
    is_active: bool


class UserOut(UserSummary):
    created_at: datetime
    updated_at: datetime


class UserCreate(BaseModel):
    email: EmailAddress
    full_name: str = Field(min_length=1, max_length=200)
    password: str = Field(min_length=12, max_length=200)
    role: Role = Role.ASSESSOR


class UserUpdate(BaseModel):
    full_name: str | None = Field(default=None, min_length=1, max_length=200)
    role: Role | None = None
    is_active: bool | None = None
    password: str | None = Field(default=None, min_length=12, max_length=200)


TokenResponse.model_rebuild()
