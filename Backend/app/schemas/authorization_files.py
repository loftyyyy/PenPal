"""Target-ownership authorization file models."""

from __future__ import annotations

from datetime import datetime
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, Field, field_validator

AuthorizationFileStatus = Literal["pending", "verified", "expired", "revoked"]


class AuthorizationFileCreate(BaseModel):
    expires_in_hours: int = Field(default=24, ge=1, le=720)
    verification_path: str = Field(
        default="/.well-known/penpal-verification.txt",
        min_length=1,
        max_length=255,
    )

    @field_validator("verification_path")
    @classmethod
    def _valid_path(cls, value: str) -> str:
        text = value.strip()
        parts = urlsplit(text)
        if (
            not text.startswith("/")
            or parts.scheme
            or parts.netloc
            or parts.query
            or parts.fragment
            or ".." in text.split("/")
            or "\\" in text
            or "\x00" in text
            or any(character.isspace() for character in text)
        ):
            raise ValueError(
                "verification_path must be an absolute path without spaces, "
                "query, fragment or dot segments"
            )
        return text


class AuthorizationFileOut(BaseModel):
    id: int
    assessment_id: int
    created_by: int | None
    target: str
    token: str
    content: str
    verification_path: str
    verification_url: str
    status: AuthorizationFileStatus
    expires_at: datetime
    revoked_at: datetime | None
    verified_at: datetime | None
    last_checked_at: datetime | None
    failure_reason: str | None
    created_at: datetime
    updated_at: datetime
