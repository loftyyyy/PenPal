"""HTTP check configuration and write-only test accounts."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends

from app.core.config import Settings, get_settings
from app.core.deps import CurrentUser, DbSession, get_assessment_or_404
from app.schemas.http_checks import (
    HttpCheckConfigIn,
    HttpCheckConfigOut,
    TestAccountCreate,
    TestAccountOut,
)
from app.services import http_checks as service

router = APIRouter(tags=["HTTP Checks"])

SettingsDep = Annotated[Settings, Depends(get_settings)]


@router.get(
    "/assessments/{assessment_id}/http-check-config",
    response_model=HttpCheckConfigOut,
    summary="Read the HTTP checks configuration",
)
async def get_http_check_config(
    assessment_id: int, db: DbSession, user: CurrentUser
) -> HttpCheckConfigOut:
    await get_assessment_or_404(db, assessment_id)
    config = await service.get_config(db, assessment_id)
    if config is None:
        from app.core.errors import NotFoundError

        raise NotFoundError("HTTP check configuration", assessment_id)
    return HttpCheckConfigOut.model_validate(config)


@router.put(
    "/assessments/{assessment_id}/http-check-config",
    response_model=HttpCheckConfigOut,
    summary="Create or replace the HTTP checks configuration",
)
async def put_http_check_config(
    assessment_id: int,
    payload: HttpCheckConfigIn,
    db: DbSession,
    user: CurrentUser,
) -> HttpCheckConfigOut:
    assessment = await get_assessment_or_404(db, assessment_id)
    config = await service.upsert_config(db, assessment, payload, user)
    return HttpCheckConfigOut.model_validate(config)


@router.get(
    "/assessments/{assessment_id}/test-accounts",
    response_model=list[TestAccountOut],
    summary="List configured test accounts (passwords are never returned)",
)
async def list_test_accounts(
    assessment_id: int, db: DbSession, user: CurrentUser
) -> list[TestAccountOut]:
    await get_assessment_or_404(db, assessment_id)
    rows = await service.list_accounts(db, assessment_id)
    return [TestAccountOut.model_validate(row) for row in rows]


@router.post(
    "/assessments/{assessment_id}/test-accounts",
    response_model=TestAccountOut,
    status_code=201,
    summary="Add a test account for HTTP checks",
    description=(
        "Passwords are write-only, never returned, never logged, and stored "
        "encrypted with CREDENTIALS_KEY."
    ),
)
async def create_test_account(
    assessment_id: int,
    payload: TestAccountCreate,
    db: DbSession,
    user: CurrentUser,
    settings: SettingsDep,
) -> TestAccountOut:
    assessment = await get_assessment_or_404(db, assessment_id)
    account = await service.create_account(
        db, assessment, payload, user, settings
    )
    return TestAccountOut.model_validate(account)


@router.delete(
    "/assessments/{assessment_id}/test-accounts/{account_id}",
    status_code=204,
    response_model=None,
    summary="Delete a test account",
)
async def delete_test_account(
    assessment_id: int,
    account_id: int,
    db: DbSession,
    user: CurrentUser,
) -> None:
    await get_assessment_or_404(db, assessment_id)
    await service.delete_account(db, assessment_id, account_id, user)
