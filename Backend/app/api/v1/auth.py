"""Authentication routes."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from app.core.config import Settings, get_settings
from app.core.deps import CurrentUser, DbSession
from app.core.errors import AppError
from app.core.security import create_access_token
from app.schemas.auth import LoginRequest, TokenResponse, UserOut
from app.schemas.common import ErrorResponse
from app.services import audit
from app.services.auth import authenticate, login_limiter

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/auth", tags=["Auth"])


@router.post(
    "/login",
    response_model=TokenResponse,
    responses={
        401: {"model": ErrorResponse, "description": "Invalid credentials"},
        429: {"model": ErrorResponse, "description": "Too many attempts"},
    },
    summary="Log in and receive a JWT access token",
)
async def login(
    payload: LoginRequest,
    request: Request,
    db: DbSession,
    settings: Settings = Depends(get_settings),
) -> TokenResponse | JSONResponse:
    client_ip = request.client.host if request.client else "unknown"
    retry_after = login_limiter.retry_after(str(payload.email), client_ip)
    if retry_after:
        return JSONResponse(
            status_code=429,
            headers={"Retry-After": str(retry_after)},
            content={
                "error": {
                    "code": "too_many_attempts",
                    "message": "Too many failed logins. Try again later.",
                    "details": {"retry_after_seconds": retry_after},
                }
            },
        )

    user = await authenticate(db, str(payload.email), payload.password)
    if user is None:
        retry_after = login_limiter.record_failure(str(payload.email), client_ip)
        await audit.record(
            db,
            "auth.login_failed",
            details={"email": str(payload.email), "client_ip": client_ip},
        )
        await db.commit()
        if retry_after:
            return JSONResponse(
                status_code=429,
                headers={"Retry-After": str(retry_after)},
                content={
                    "error": {
                        "code": "too_many_attempts",
                        "message": "Too many failed logins. Try again later.",
                        "details": {"retry_after_seconds": retry_after},
                    }
                },
            )
        raise AppError(401, "invalid_credentials", "Invalid email or password")

    login_limiter.reset(str(payload.email), client_ip)
    await audit.record(
        db,
        "auth.login_success",
        user_id=user.id,
        entity_type="user",
        entity_id=user.id,
        details={"email": user.email, "client_ip": client_ip},
    )
    await db.commit()

    token = create_access_token(user.id)
    return TokenResponse(
        access_token=token,
        expires_in=settings.access_token_expire_minutes * 60,
        user=user,
    )


@router.get(
    "/me",
    response_model=UserOut,
    summary="Current authenticated user",
)
async def me(user: CurrentUser) -> UserOut:
    return UserOut.model_validate(user)
