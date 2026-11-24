"""Static metadata the frontend must not hard-code."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel

from app.core.deps import CurrentUser
from app.services.severity import matrix_metadata

router = APIRouter(tags=["Metadata"])


class SeverityMatrixOut(BaseModel):
    likelihood: dict[str, Any]
    impact: dict[str, Any]
    thresholds: list[dict[str, Any]]
    formula: str
    final_severity_source: str


@router.get(
    "/meta/severity-matrix",
    response_model=SeverityMatrixOut,
    summary="Likelihood x impact severity matrix",
    description=(
        "Returns the 1-5 scales, labels and inclusive score thresholds. "
        "The server computes final severity; clients must not."
    ),
)
async def get_severity_matrix(user: CurrentUser) -> SeverityMatrixOut:
    return SeverityMatrixOut(**matrix_metadata())
