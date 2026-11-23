"""Helpers shared by API tests."""

from __future__ import annotations

from app.core.security import hash_password
from app.db.enums import Role
from app.db.models import User
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

PASSWORD = "correct-horse-battery-staple"


async def create_user(
    db: AsyncSession,
    *,
    email: str,
    role: Role = Role.ASSESSOR,
    password: str = PASSWORD,
    is_active: bool = True,
    full_name: str = "Test User",
) -> User:
    user = User(
        email=email.lower(),
        full_name=full_name,
        password_hash=hash_password(password),
        role=role,
        is_active=is_active,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


async def login_headers(
    client: AsyncClient, email: str, password: str = PASSWORD
) -> dict[str, str]:
    response = await client.post(
        "/api/v1/auth/login", json={"email": email, "password": password}
    )
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}
