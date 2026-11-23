"""Administrator user management."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Query
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import AdminUser, DbSession, PaginationParams
from app.core.errors import AppError, ConflictError, NotFoundError
from app.core.security import hash_password
from app.db.enums import Role
from app.db.models import User
from app.schemas.auth import UserCreate, UserOut, UserUpdate
from app.schemas.common import Page
from app.services import audit

router = APIRouter(prefix="/users", tags=["Users"])


async def _active_admin_count(db: AsyncSession, excluding_id: int | None = None) -> int:
    query = select(func.count(User.id)).where(
        User.role == Role.ADMIN, User.is_active.is_(True)
    )
    if excluding_id is not None:
        query = query.where(User.id != excluding_id)
    return int(await db.scalar(query) or 0)


@router.post(
    "",
    response_model=UserOut,
    status_code=201,
    summary="Create a user (admin only)",
)
async def create_user(
    payload: UserCreate,
    db: DbSession,
    admin: AdminUser,
) -> UserOut:
    email = str(payload.email).strip().lower()
    existing = await db.scalar(select(User).where(User.email == email))
    if existing is not None:
        raise ConflictError("A user with that email already exists")
    user = User(
        email=email,
        full_name=payload.full_name.strip(),
        password_hash=hash_password(payload.password),
        role=payload.role,
        is_active=True,
    )
    db.add(user)
    await db.flush()
    await audit.record(
        db,
        "user.created",
        user_id=admin.id,
        entity_type="user",
        entity_id=user.id,
        details={"email": user.email, "role": user.role},
    )
    await db.commit()
    await db.refresh(user)
    return UserOut.model_validate(user)


@router.get(
    "",
    response_model=Page[UserOut],
    summary="List users (admin only)",
)
async def list_users(
    db: DbSession,
    admin: AdminUser,
    pagination: PaginationParams,
    q: Annotated[str | None, Query(max_length=200)] = None,
    role: Annotated[Role | None, Query()] = None,
    is_active: Annotated[bool | None, Query()] = None,
) -> Page[UserOut]:
    filters = []
    if q:
        needle = f"%{q.strip().lower()}%"
        filters.append(or_(User.email.ilike(needle), User.full_name.ilike(needle)))
    if role is not None:
        filters.append(User.role == role)
    if is_active is not None:
        filters.append(User.is_active.is_(is_active))

    total = int(await db.scalar(select(func.count(User.id)).where(*filters)) or 0)
    result = await db.execute(
        select(User)
        .where(*filters)
        .order_by(User.id)
        .offset(pagination.offset)
        .limit(pagination.page_size)
    )
    users = result.scalars().all()
    return Page[UserOut](
        items=[UserOut.model_validate(user) for user in users],
        total=total,
        page=pagination.page,
        page_size=pagination.page_size,
    )


@router.patch(
    "/{user_id}",
    response_model=UserOut,
    summary="Update role, active state, name or password (admin only)",
)
async def update_user(
    user_id: int,
    payload: UserUpdate,
    db: DbSession,
    admin: AdminUser,
) -> UserOut:
    user = await db.get(User, user_id)
    if user is None:
        raise NotFoundError("User", user_id)

    previous = {"role": user.role, "is_active": user.is_active}
    becoming_non_admin = payload.role is not None and payload.role != Role.ADMIN
    becoming_inactive = payload.is_active is False
    if user.id == admin.id and (becoming_non_admin or becoming_inactive):
        raise AppError(
            422,
            "self_lockout",
            "An administrator cannot demote or deactivate their own account",
        )
    if (
        (becoming_non_admin or becoming_inactive)
        and user.role == Role.ADMIN
        and await _active_admin_count(db, excluding_id=user.id) == 0
    ):
        raise AppError(
            422,
            "last_admin",
            "The last active administrator cannot be removed",
        )

    if payload.full_name is not None:
        user.full_name = payload.full_name.strip()
    if payload.role is not None:
        user.role = payload.role
    if payload.is_active is not None:
        user.is_active = payload.is_active
    if payload.password is not None:
        user.password_hash = hash_password(payload.password)

    await audit.record(
        db,
        "user.updated",
        user_id=admin.id,
        entity_type="user",
        entity_id=user.id,
        details={
            "previous": previous,
            "new": {"role": user.role, "is_active": user.is_active},
            "password_reset": payload.password is not None,
        },
    )
    await db.commit()
    await db.refresh(user)
    return UserOut.model_validate(user)
