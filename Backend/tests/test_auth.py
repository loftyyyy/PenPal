from __future__ import annotations

from app.core.security import create_access_token
from app.db.enums import Role
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from tests.utils import PASSWORD, create_user, login_headers


async def test_login_success_and_me(client: AsyncClient, db: AsyncSession) -> None:
    user = await create_user(db, email="assessor@example.test", full_name="Ada Assessor")
    response = await client.post(
        "/api/v1/auth/login", json={"email": user.email, "password": PASSWORD}
    )
    assert response.status_code == 200
    body = response.json()
    assert body["token_type"] == "bearer"
    assert body["user"]["email"] == user.email
    assert body["expires_in"] == 3600

    headers = {"Authorization": f"Bearer {body['access_token']}"}
    me = await client.get("/api/v1/auth/me", headers=headers)
    assert me.status_code == 200
    assert me.json()["role"] == "assessor"


async def test_login_is_case_insensitive_on_email(
    client: AsyncClient, db: AsyncSession
) -> None:
    await create_user(db, email="mixed@example.test")
    response = await client.post(
        "/api/v1/auth/login", json={"email": "MIXED@example.test", "password": PASSWORD}
    )
    assert response.status_code == 200


async def test_login_wrong_password(client: AsyncClient, db: AsyncSession) -> None:
    user = await create_user(db, email="wrong@example.test")
    response = await client.post(
        "/api/v1/auth/login", json={"email": user.email, "password": "nope"}
    )
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "invalid_credentials"


async def test_inactive_user_cannot_log_in(client: AsyncClient, db: AsyncSession) -> None:
    user = await create_user(db, email="inactive@example.test", is_active=False)
    response = await client.post(
        "/api/v1/auth/login", json={"email": user.email, "password": PASSWORD}
    )
    assert response.status_code == 401


async def test_invalid_and_expired_tokens(client: AsyncClient, db: AsyncSession) -> None:
    user = await create_user(db, email="token@example.test")
    bad = await client.get(
        "/api/v1/auth/me", headers={"Authorization": "Bearer not-a-jwt"}
    )
    assert bad.status_code == 401
    assert bad.json()["error"]["code"] == "invalid_token"

    expired = create_access_token(user.id, expires_minutes=-1)
    response = await client.get(
        "/api/v1/auth/me", headers={"Authorization": f"Bearer {expired}"}
    )
    assert response.status_code == 401


async def test_missing_token(client: AsyncClient) -> None:
    response = await client.get("/api/v1/auth/me")
    assert response.status_code == 401


async def test_login_rate_limit(client: AsyncClient, db: AsyncSession) -> None:
    await create_user(db, email="bruteforce@example.test")
    for _ in range(4):
        response = await client.post(
            "/api/v1/auth/login",
            json={"email": "bruteforce@example.test", "password": "wrong"},
        )
        assert response.status_code == 401
    fifth = await client.post(
        "/api/v1/auth/login",
        json={"email": "bruteforce@example.test", "password": "wrong"},
    )
    assert fifth.status_code == 429
    assert fifth.headers["retry-after"]
    # Even the correct password is blocked while the lockout stands.
    blocked = await client.post(
        "/api/v1/auth/login",
        json={"email": "bruteforce@example.test", "password": PASSWORD},
    )
    assert blocked.status_code == 429


async def test_assessor_cannot_manage_users(client: AsyncClient, db: AsyncSession) -> None:
    await create_user(db, email="plain@example.test", role=Role.ASSESSOR)
    headers = await login_headers(client, "plain@example.test")
    response = await client.get("/api/v1/users", headers=headers)
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "forbidden"


async def test_admin_user_lifecycle(client: AsyncClient, db: AsyncSession) -> None:
    await create_user(db, email="root@example.test", role=Role.ADMIN)
    headers = await login_headers(client, "root@example.test")

    created = await client.post(
        "/api/v1/users",
        headers=headers,
        json={
            "email": "new@example.test",
            "full_name": "New Person",
            "password": "a-long-enough-password",
            "role": "assessor",
        },
    )
    assert created.status_code == 201, created.text
    user_id = created.json()["id"]

    duplicate = await client.post(
        "/api/v1/users",
        headers=headers,
        json={
            "email": "new@example.test",
            "full_name": "New Person",
            "password": "a-long-enough-password",
        },
    )
    assert duplicate.status_code == 409

    listed = await client.get("/api/v1/users", headers=headers)
    assert listed.status_code == 200
    assert listed.json()["total"] == 2
    assert listed.json()["items"][0]["email"] == "root@example.test"

    promoted = await client.patch(
        f"/api/v1/users/{user_id}", headers=headers, json={"role": "admin"}
    )
    assert promoted.status_code == 200
    assert promoted.json()["role"] == "admin"

    reset = await client.patch(
        f"/api/v1/users/{user_id}",
        headers=headers,
        json={"password": "another-long-password"},
    )
    assert reset.status_code == 200
    old_login = await client.post(
        "/api/v1/auth/login",
        json={"email": "new@example.test", "password": "a-long-enough-password"},
    )
    assert old_login.status_code == 401
    new_login = await client.post(
        "/api/v1/auth/login",
        json={"email": "new@example.test", "password": "another-long-password"},
    )
    assert new_login.status_code == 200

    deactivated = await client.patch(
        f"/api/v1/users/{user_id}", headers=headers, json={"is_active": False}
    )
    assert deactivated.status_code == 200
    assert deactivated.json()["is_active"] is False


async def test_admin_cannot_deactivate_self(client: AsyncClient, db: AsyncSession) -> None:
    admin = await create_user(db, email="self@example.test", role=Role.ADMIN)
    headers = await login_headers(client, admin.email)
    response = await client.patch(
        f"/api/v1/users/{admin.id}", headers=headers, json={"is_active": False}
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "self_lockout"


async def test_password_policy_enforced(client: AsyncClient, db: AsyncSession) -> None:
    await create_user(db, email="policy@example.test", role=Role.ADMIN)
    headers = await login_headers(client, "policy@example.test")
    response = await client.post(
        "/api/v1/users",
        headers=headers,
        json={"email": "short@example.test", "full_name": "Short", "password": "short"},
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"
