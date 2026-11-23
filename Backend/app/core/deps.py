"""Shared FastAPI dependencies."""

from __future__ import annotations

from typing import Annotated

import jwt
from fastapi import Depends, Query
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import AppError, NotFoundError
from app.core.security import decode_access_token
from app.db.models import Assessment, User
from app.db.session import get_db

DbSession = Annotated[AsyncSession, Depends(get_db)]

_bearer = HTTPBearer(auto_error=False, description="JWT access token")


async def get_current_user(
    db: DbSession,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)] = None,
) -> User:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise AppError(401, "not_authenticated", "Authentication required")
    try:
        payload = decode_access_token(credentials.credentials)
        user_id = int(payload["sub"])
    except (jwt.PyJWTError, KeyError, ValueError, TypeError) as exc:
        raise AppError(401, "invalid_token", "Token is invalid or expired") from exc

    user = await db.get(User, user_id)
    if user is None or not user.is_active:
        raise AppError(401, "invalid_token", "Token is invalid or expired")
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


async def require_admin(user: CurrentUser) -> User:
    if user.role != "admin":
        raise AppError(403, "forbidden", "Administrator role required")
    return user


AdminUser = Annotated[User, Depends(require_admin)]


async def get_assessment_or_404(db: AsyncSession, assessment_id: int) -> Assessment:
    assessment = await db.get(Assessment, assessment_id)
    if assessment is None:
        raise NotFoundError("Assessment", assessment_id)
    return assessment


class Pagination:
    def __init__(
        self,
        page: int = Query(1, ge=1, description="1-based page number"),
        page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    ) -> None:
        self.page = page
        self.page_size = page_size
        self.offset = (page - 1) * page_size


PaginationParams = Annotated[Pagination, Depends(Pagination)]


async def user_by_email(db: AsyncSession, email: str) -> User | None:
    result = await db.execute(select(User).where(User.email == email.lower()))
    return result.scalar_one_or_none()
