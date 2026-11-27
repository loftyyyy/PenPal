"""Management endpoints for target-ownership authorization files."""

from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import PlainTextResponse

from app.core.deps import CurrentUser, DbSession, get_assessment_or_404
from app.schemas.authorization_files import (
    AuthorizationFileCreate,
    AuthorizationFileOut,
)
from app.services import authorization_files as service

router = APIRouter(tags=["Authorization files"])


@router.post(
    "/assessments/{assessment_id}/authorization-files",
    response_model=AuthorizationFileOut,
    status_code=201,
    summary="Create a target-ownership verification token",
    description=(
        "The assessment creator (or an admin) gets a unique token to publish at "
        "the configured path on the assessment target. Creating a new token revokes "
        "the previous active token for the same target."
    ),
)
async def create_authorization_file(
    assessment_id: int,
    payload: AuthorizationFileCreate,
    db: DbSession,
    user: CurrentUser,
) -> AuthorizationFileOut:
    assessment = await get_assessment_or_404(db, assessment_id)
    record = await service.create_authorization_file(db, assessment, user, payload)
    return service.to_out(record)


@router.get(
    "/assessments/{assessment_id}/authorization-files",
    response_model=list[AuthorizationFileOut],
    summary="List authorization files for an assessment",
)
async def list_authorization_files(
    assessment_id: int, db: DbSession, user: CurrentUser
) -> list[AuthorizationFileOut]:
    assessment = await get_assessment_or_404(db, assessment_id)
    records = await service.list_authorization_files(db, assessment, user)
    return [service.to_out(record) for record in records]


@router.get(
    "/authorization-files/{file_id}",
    response_model=AuthorizationFileOut,
    summary="Inspect an authorization file",
)
async def get_authorization_file(
    file_id: int, db: DbSession, user: CurrentUser
) -> AuthorizationFileOut:
    record = await service.get_authorization_file(db, file_id, user)
    return service.to_out(record)


@router.get(
    "/authorization-files/{file_id}/file",
    response_class=PlainTextResponse,
    summary="Download the verification token file",
    description="Returns the exact text to publish at the verification path.",
)
async def download_authorization_file(
    file_id: int, db: DbSession, user: CurrentUser
) -> PlainTextResponse:
    record = await service.get_authorization_file(db, file_id, user)
    return PlainTextResponse(
        record.token,
        media_type="text/plain",
        headers={
            "Content-Disposition": 'attachment; filename="penpal-verification.txt"'
        },
    )


@router.post(
    "/authorization-files/{file_id}/verify",
    response_model=AuthorizationFileOut,
    summary="Verify the token at the target's well-known path",
    description=(
        "Fetches the configured path from the assessment target and compares it "
        "with the token. Redirects are not followed and only the first 4 KiB are read."
    ),
)
async def verify_authorization_file(
    file_id: int, db: DbSession, user: CurrentUser
) -> AuthorizationFileOut:
    record = await service.verify_authorization_file(db, file_id, user)
    return service.to_out(record)


@router.post(
    "/authorization-files/{file_id}/revoke",
    response_model=AuthorizationFileOut,
    summary="Revoke an authorization file",
)
async def revoke_authorization_file(
    file_id: int, db: DbSession, user: CurrentUser
) -> AuthorizationFileOut:
    record = await service.revoke_authorization_file(db, file_id, user)
    return service.to_out(record)
