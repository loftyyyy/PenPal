from __future__ import annotations

from app.db.enums import AssessmentStatus, Role, ScopeKind
from app.db.models import AuditLog
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from tests.utils import (
    add_scope,
    create_assessment,
    create_user,
    login_headers,
)


async def setup_assessor(client: AsyncClient, db: AsyncSession, email: str = "a@example.test"):
    await create_user(db, email=email)
    return await login_headers(client, email)


async def test_assessment_crud_and_authorization(
    client: AsyncClient, db: AsyncSession
) -> None:
    await create_user(db, email="owner@example.test", role=Role.ASSESSOR)
    headers = await login_headers(client, "owner@example.test")

    created = await client.post(
        "/api/v1/assessments",
        headers=headers,
        json={
            "name": "LSRS assessment",
            "target_name": "LSRS",
            "target_base_url": "http://localhost:3000",
            "owner_name": "Rho",
            "authorization_reference": "letter.pdf",
            "selected_categories": ["authentication", "access_control"],
        },
    )
    assert created.status_code == 201, created.text
    assessment_id = created.json()["id"]
    assert created.json()["status"] == "draft"
    assert created.json()["authorization_confirmed"] is False

    # Ready requires confirmation.
    premature = await client.patch(
        f"/api/v1/assessments/{assessment_id}",
        headers=headers,
        json={"status": "ready"},
    )
    assert premature.status_code == 403

    confirmed = await client.post(
        f"/api/v1/assessments/{assessment_id}/confirm-authorization",
        headers=headers,
        json={"note": "signed letter on file"},
    )
    assert confirmed.status_code == 200
    assert confirmed.json()["authorization_confirmed"] is True
    assert confirmed.json()["status"] == "ready"
    assert confirmed.json()["authorization_confirmed_at"]

    updated = await client.patch(
        f"/api/v1/assessments/{assessment_id}",
        headers=headers,
        json={"description": "updated", "status": "in_progress"},
    )
    assert updated.status_code == 200
    assert updated.json()["status"] == "in_progress"

    listed = await client.get("/api/v1/assessments", headers=headers)
    assert listed.status_code == 200
    assert listed.json()["total"] == 1

    archived = await client.post(
        f"/api/v1/assessments/{assessment_id}/archive", headers=headers
    )
    assert archived.status_code == 200
    assert archived.json()["status"] == "archived"

    blocked = await client.patch(
        f"/api/v1/assessments/{assessment_id}",
        headers=headers,
        json={"status": "archived"},
    )
    assert blocked.status_code == 403


async def test_assessment_requires_auth(client: AsyncClient) -> None:
    response = await client.get("/api/v1/assessments")
    assert response.status_code == 401


async def test_assessment_target_url_validation(
    client: AsyncClient, db: AsyncSession
) -> None:
    headers = await setup_assessor(client, db)
    response = await client.post(
        "/api/v1/assessments",
        headers=headers,
        json={
            "name": "bad",
            "target_name": "bad",
            "target_base_url": "ftp://example.test",
            "owner_name": "owner",
            "authorization_reference": "letter",
        },
    )
    assert response.status_code == 422


async def test_scope_crud_normalises_values(
    client: AsyncClient, db: AsyncSession
) -> None:
    headers = await setup_assessor(client, db)
    user = await create_user(db, email="second@example.test")
    assessment = await create_assessment(db, user=user)

    created = await client.post(
        f"/api/v1/assessments/{assessment.id}/scope-items",
        headers=headers,
        json={"kind": "host", "value": "LOCALHOST."},
    )
    assert created.status_code == 201, created.text
    assert created.json()["value"] == "localhost"

    duplicate = await client.post(
        f"/api/v1/assessments/{assessment.id}/scope-items",
        headers=headers,
        json={"kind": "host", "value": "localhost"},
    )
    assert duplicate.status_code == 409

    invalid = await client.post(
        f"/api/v1/assessments/{assessment.id}/scope-items",
        headers=headers,
        json={"kind": "cidr", "value": "not-a-cidr"},
    )
    assert invalid.status_code == 422
    assert invalid.json()["error"]["code"] == "invalid_scope_value"

    listed = await client.get(
        f"/api/v1/assessments/{assessment.id}/scope-items", headers=headers
    )
    assert listed.status_code == 200
    assert len(listed.json()) == 1

    deleted = await client.delete(
        f"/api/v1/assessments/{assessment.id}/scope-items/{created.json()['id']}",
        headers=headers,
    )
    assert deleted.status_code == 204
    listed_again = await client.get(
        f"/api/v1/assessments/{assessment.id}/scope-items", headers=headers
    )
    assert listed_again.json() == []


async def test_scope_check_endpoint(client: AsyncClient, db: AsyncSession) -> None:
    user = await create_user(db, email="scope@example.test")
    headers = await login_headers(client, "scope@example.test")
    assessment = await create_assessment(db, user=user, authorized=False)
    await add_scope(db, assessment, ScopeKind.HOST, "localhost")

    denied = await client.post(
        f"/api/v1/assessments/{assessment.id}/scope/check",
        headers=headers,
        json={"target": "http://localhost:3000/", "tool": "zap"},
    )
    assert denied.status_code == 200
    assert denied.json()["allowed"] is False
    assert "authorization" in denied.json()["reasons"][0]

    await client.post(
        f"/api/v1/assessments/{assessment.id}/confirm-authorization",
        headers=headers,
        json={},
    )
    allowed = await client.post(
        f"/api/v1/assessments/{assessment.id}/scope/check",
        headers=headers,
        json={"target": "http://localhost:3000/", "tool": "zap"},
    )
    assert allowed.status_code == 200, allowed.text
    assert allowed.json()["allowed"] is True
    assert set(allowed.json()["resolved_ips"]) == {"127.0.0.1", "::1"}

    public = await client.post(
        f"/api/v1/assessments/{assessment.id}/scope/check",
        headers=headers,
        json={"target": "http://8.8.8.8/", "tool": "zap"},
    )
    assert public.json()["allowed"] is False

    audits = (
        await db.execute(
            select(AuditLog).where(AuditLog.action == "scope.checked")
        )
    ).scalars().all()
    assert len(audits) == 3
    assert audits[0].details["allowed"] is False


async def test_archived_assessment_cannot_change_scope(
    client: AsyncClient, db: AsyncSession
) -> None:
    user = await create_user(db, email="archived@example.test")
    headers = await login_headers(client, "archived@example.test")
    assessment = await create_assessment(db, user=user, authorized=True)
    assessment.status = AssessmentStatus.ARCHIVED
    await db.commit()

    response = await client.post(
        f"/api/v1/assessments/{assessment.id}/scope-items",
        headers=headers,
        json={"kind": "host", "value": "localhost"},
    )
    assert response.status_code == 403
