"""Helpers shared by API tests."""

from __future__ import annotations

from app.core.security import hash_password
from app.db.enums import AssessmentStatus, Role, ScopeKind
from app.db.models import Assessment, ScopeItem, User
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


async def create_assessment(
    db: AsyncSession,
    *,
    user: User,
    name: str = "LSRS test assessment",
    target_base_url: str | None = "http://localhost:3000",
    authorized: bool = False,
) -> Assessment:
    assessment = Assessment(
        name=name,
        target_name="Love & Styles Rental System",
        target_base_url=target_base_url,
        owner_name="LSRS owners",
        authorization_reference="signed-authorization-letter.pdf",
        authorization_confirmed=authorized,
        authorization_confirmed_by=user.id if authorized else None,
        status=AssessmentStatus.READY if authorized else AssessmentStatus.DRAFT,
        selected_categories=["authentication", "access_control"],
        created_by=user.id,
    )
    db.add(assessment)
    await db.commit()
    await db.refresh(assessment)
    return assessment


async def add_scope(
    db: AsyncSession,
    assessment: Assessment,
    kind: ScopeKind,
    value: str,
    *,
    in_scope: bool = True,
) -> ScopeItem:
    item = ScopeItem(
        assessment_id=assessment.id,
        kind=kind,
        value=value,
        in_scope=in_scope,
    )
    db.add(item)
    await db.commit()
    await db.refresh(item)
    return item
