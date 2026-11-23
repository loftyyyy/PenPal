"""Scope item management and the dry-run scope check."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select

from app.core.config import Settings, get_settings
from app.core.deps import CurrentUser, DbSession, get_assessment_or_404
from app.core.errors import NotFoundError
from app.db.enums import ScanTool, ScopeKind
from app.db.models import ScopeItem
from app.schemas.assessments import (
    ScopeCheckRequest,
    ScopeCheckResponse,
    ScopeItemCreate,
    ScopeItemOut,
)
from app.services import assessments as service
from app.services.scope_guard import ScopeGuard, TargetError

router = APIRouter(prefix="/assessments/{assessment_id}", tags=["Scope"])


async def _assessment(db: DbSession, assessment_id: int):
    return await get_assessment_or_404(db, assessment_id)


@router.post(
    "/scope-items",
    response_model=ScopeItemOut,
    status_code=201,
    summary="Add an in-scope or out-of-scope rule",
    description=(
        "Values are canonicalised. Host rules are exact unless written as "
        "'*.example.test'. CIDR rules are normalised to the network address."
    ),
)
async def add_scope_item(
    assessment_id: int,
    payload: ScopeItemCreate,
    db: DbSession,
    user: CurrentUser,
) -> ScopeItemOut:
    assessment = await _assessment(db, assessment_id)
    item = await service.add_scope_item(db, assessment, payload, user)
    return ScopeItemOut.model_validate(item)


@router.get(
    "/scope-items",
    response_model=list[ScopeItemOut],
    summary="List scope rules",
)
async def list_scope_items(
    assessment_id: int,
    db: DbSession,
    user: CurrentUser,
    kind: Annotated[ScopeKind | None, Query()] = None,
    in_scope: Annotated[bool | None, Query()] = None,
) -> list[ScopeItemOut]:
    await _assessment(db, assessment_id)
    query = select(ScopeItem).where(ScopeItem.assessment_id == assessment_id)
    if kind is not None:
        query = query.where(ScopeItem.kind == kind)
    if in_scope is not None:
        query = query.where(ScopeItem.in_scope.is_(in_scope))
    result = await db.execute(query.order_by(ScopeItem.kind, ScopeItem.value))
    return [ScopeItemOut.model_validate(item) for item in result.scalars().all()]


@router.delete(
    "/scope-items/{item_id}",
    status_code=204,
    response_model=None,
    summary="Delete a scope rule",
)
async def delete_scope_item(
    assessment_id: int,
    item_id: int,
    db: DbSession,
    user: CurrentUser,
) -> None:
    assessment = await _assessment(db, assessment_id)
    item = await db.scalar(
        select(ScopeItem).where(
            ScopeItem.id == item_id, ScopeItem.assessment_id == assessment_id
        )
    )
    if item is None:
        raise NotFoundError("Scope item", item_id)
    await service.delete_scope_item(db, assessment, item, user)


@router.post(
    "/scope/check",
    response_model=ScopeCheckResponse,
    summary="Dry-run the scope guard",
    description=(
        "Returns the verdict and specific reasons without starting a scan. "
        "The check is audited. Out-of-scope rules beat in-scope rules, DNS is "
        "resolved, and public addresses are rejected by default."
    ),
)
async def check_scope(
    assessment_id: int,
    payload: ScopeCheckRequest,
    db: DbSession,
    user: CurrentUser,
    settings: Settings = Depends(get_settings),
) -> ScopeCheckResponse:
    assessment = await _assessment(db, assessment_id)
    try:
        ports = service.validate_ports(payload.ports)
    except TargetError as exc:
        return ScopeCheckResponse(allowed=False, reasons=[str(exc)])
    guard = ScopeGuard(settings)
    decision = await service.check_scope(
        db,
        assessment,
        guard,
        payload.target,
        ScanTool(payload.tool),
        ports,
        user,
        context="dry_run",
    )
    return ScopeCheckResponse(**decision.summary())
