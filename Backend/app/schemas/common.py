"""Shared response envelopes and error model for OpenAPI."""

from __future__ import annotations

from typing import Annotated, Generic, TypeVar

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

T = TypeVar("T")

# EmailStr rejects reserved domains such as .test and .local. PenPal is a local
# tool and the first admin address commonly uses a local domain, so validate the
# shape here instead and store lowercase.
EmailAddress = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        to_lower=True,
        min_length=5,
        max_length=255,
        pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$",
    ),
]


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class Page(BaseModel, Generic[T]):
    items: list[T]
    total: int = Field(ge=0)
    page: int = Field(ge=1)
    page_size: int = Field(ge=1)


class ErrorDetail(BaseModel):
    code: str
    message: str
    details: object | None = None


class ErrorResponse(BaseModel):
    error: ErrorDetail
