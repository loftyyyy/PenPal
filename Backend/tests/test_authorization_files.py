from __future__ import annotations

from datetime import timedelta

import httpx
import pytest
from app.db.base import utcnow
from app.db.enums import Role
from app.db.models import AuthorizationFile
from app.services import authorization_files as service
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from tests.utils import create_assessment, create_user, login_headers


async def _setup(
    client: AsyncClient,
    db: AsyncSession,
    *,
    email: str = "authorization-owner@example.test",
    target: str | None = "http://localhost:3000",
):
    user = await create_user(db, email=email)
    headers = await login_headers(client, email)
    assessment = await create_assessment(db, user=user, target_base_url=target)
    return user, headers, assessment


async def test_create_list_download_and_rotate_authorization_files(
    client: AsyncClient, db: AsyncSession
) -> None:
    _, headers, assessment = await _setup(client, db)

    first = await client.post(
        f"/api/v1/assessments/{assessment.id}/authorization-files",
        headers=headers,
        json={"expires_in_hours": 2},
    )
    assert first.status_code == 201, first.text
    first_body = first.json()
    assert first_body["status"] == "pending"
    assert first_body["target"] == "http://localhost:3000"
    assert first_body["verification_path"] == "/.well-known/penpal-verification.txt"
    assert first_body["verification_url"].endswith(
        "/.well-known/penpal-verification.txt"
    )
    assert first_body["content"] == first_body["token"]
    assert len(first_body["token"]) >= 32

    downloaded = await client.get(
        f"/api/v1/authorization-files/{first_body['id']}/file", headers=headers
    )
    assert downloaded.status_code == 200
    assert downloaded.text == first_body["token"]
    assert "attachment" in downloaded.headers["content-disposition"]

    second = await client.post(
        f"/api/v1/assessments/{assessment.id}/authorization-files",
        headers=headers,
        json={},
    )
    assert second.status_code == 201, second.text
    assert second.json()["token"] != first_body["token"]

    listed = await client.get(
        f"/api/v1/assessments/{assessment.id}/authorization-files", headers=headers
    )
    assert listed.status_code == 200
    items = listed.json()
    assert len(items) == 2
    by_id = {item["id"]: item for item in items}
    assert by_id[first_body["id"]]["status"] == "revoked"
    assert by_id[second.json()["id"]]["status"] == "pending"


async def test_authorization_file_ownership_and_admin_access(
    client: AsyncClient, db: AsyncSession
) -> None:
    _, owner_headers, assessment = await _setup(client, db)
    created = await client.post(
        f"/api/v1/assessments/{assessment.id}/authorization-files",
        headers=owner_headers,
        json={},
    )
    assert created.status_code == 201
    file_id = created.json()["id"]

    await create_user(db, email="other-assessor@example.test")
    other_headers = await login_headers(client, "other-assessor@example.test")
    for response in (
        await client.get(
            f"/api/v1/assessments/{assessment.id}/authorization-files",
            headers=other_headers,
        ),
        await client.post(
            f"/api/v1/assessments/{assessment.id}/authorization-files",
            headers=other_headers,
            json={},
        ),
        await client.get(
            f"/api/v1/authorization-files/{file_id}", headers=other_headers
        ),
        await client.post(
            f"/api/v1/authorization-files/{file_id}/verify",
            headers=other_headers,
        ),
        await client.post(
            f"/api/v1/authorization-files/{file_id}/revoke",
            headers=other_headers,
        ),
    ):
        assert response.status_code == 403

    await create_user(
        db, email="authorization-admin@example.test", role=Role.ADMIN
    )
    admin_headers = await login_headers(client, "authorization-admin@example.test")
    admin_view = await client.get(
        f"/api/v1/authorization-files/{file_id}", headers=admin_headers
    )
    assert admin_view.status_code == 200


async def test_authorization_file_requires_authentication(
    client: AsyncClient, db: AsyncSession
) -> None:
    _, _, assessment = await _setup(client, db)
    response = await client.post(
        f"/api/v1/assessments/{assessment.id}/authorization-files", json={}
    )
    assert response.status_code == 401


async def test_verify_success_updates_status(
    client: AsyncClient,
    db: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, headers, assessment = await _setup(client, db)
    created = await client.post(
        f"/api/v1/assessments/{assessment.id}/authorization-files",
        headers=headers,
        json={},
    )
    file_id = created.json()["id"]
    token = created.json()["token"]
    calls: list[str] = []

    async def fake_fetch(url: str) -> tuple[int, str]:
        calls.append(url)
        return 200, token + "\n"

    monkeypatch.setattr(service, "fetch_verification_content", fake_fetch)
    verified = await client.post(
        f"/api/v1/authorization-files/{file_id}/verify", headers=headers
    )
    assert verified.status_code == 200, verified.text
    assert verified.json()["status"] == "verified"
    assert verified.json()["verified_at"]
    assert verified.json()["failure_reason"] is None
    assert calls == [created.json()["verification_url"]]


async def test_verify_mismatch_and_missing_file_are_clear(
    client: AsyncClient,
    db: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, headers, assessment = await _setup(client, db)
    created = await client.post(
        f"/api/v1/assessments/{assessment.id}/authorization-files",
        headers=headers,
        json={},
    )
    file_id = created.json()["id"]

    async def wrong_fetch(url: str) -> tuple[int, str]:
        return 200, "wrong-token"

    monkeypatch.setattr(service, "fetch_verification_content", wrong_fetch)
    mismatch = await client.post(
        f"/api/v1/authorization-files/{file_id}/verify", headers=headers
    )
    assert mismatch.status_code == 422
    assert mismatch.json()["error"]["code"] == "authorization_file_mismatch"
    assert mismatch.json()["error"]["details"]["url"]

    inspected = await client.get(
        f"/api/v1/authorization-files/{file_id}", headers=headers
    )
    assert inspected.json()["failure_reason"] == "token mismatch"
    assert inspected.json()["last_checked_at"]

    async def missing_fetch(url: str) -> tuple[int, str]:
        return 404, "not found"

    monkeypatch.setattr(service, "fetch_verification_content", missing_fetch)
    missing = await client.post(
        f"/api/v1/authorization-files/{file_id}/verify", headers=headers
    )
    assert missing.status_code == 422
    assert missing.json()["error"]["code"] == "authorization_file_unavailable"


async def test_verify_network_failure_is_reported(
    client: AsyncClient,
    db: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, headers, assessment = await _setup(client, db)
    created = await client.post(
        f"/api/v1/assessments/{assessment.id}/authorization-files",
        headers=headers,
        json={},
    )

    async def failed_fetch(url: str) -> tuple[int, str]:
        raise httpx.ConnectError("unreachable")

    monkeypatch.setattr(service, "fetch_verification_content", failed_fetch)
    response = await client.post(
        f"/api/v1/authorization-files/{created.json()['id']}/verify",
        headers=headers,
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "authorization_file_unreachable"


async def test_revoke_and_expiration_block_verification(
    client: AsyncClient,
    db: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, headers, assessment = await _setup(client, db)

    async def fake_fetch(url: str) -> tuple[int, str]:
        return 200, "token"

    monkeypatch.setattr(service, "fetch_verification_content", fake_fetch)

    revoked = await client.post(
        f"/api/v1/assessments/{assessment.id}/authorization-files",
        headers=headers,
        json={},
    )
    revoke = await client.post(
        f"/api/v1/authorization-files/{revoked.json()['id']}/revoke",
        headers=headers,
    )
    assert revoke.status_code == 200
    assert revoke.json()["status"] == "revoked"
    again = await client.post(
        f"/api/v1/authorization-files/{revoked.json()['id']}/revoke",
        headers=headers,
    )
    assert again.status_code == 409
    verify_revoked = await client.post(
        f"/api/v1/authorization-files/{revoked.json()['id']}/verify",
        headers=headers,
    )
    assert verify_revoked.status_code == 409
    assert verify_revoked.json()["error"]["code"] == "authorization_file_revoked"

    expiring = await client.post(
        f"/api/v1/assessments/{assessment.id}/authorization-files",
        headers=headers,
        json={},
    )
    record = await db.get(AuthorizationFile, expiring.json()["id"])
    assert record is not None
    record.expires_at = utcnow() - timedelta(seconds=1)
    await db.commit()
    expired = await client.post(
        f"/api/v1/authorization-files/{record.id}/verify", headers=headers
    )
    assert expired.status_code == 409
    assert expired.json()["error"]["code"] == "authorization_file_expired"


async def test_authorization_file_requires_target_and_valid_path(
    client: AsyncClient, db: AsyncSession
) -> None:
    _, headers, assessment = await _setup(client, db, target=None)
    missing_target = await client.post(
        f"/api/v1/assessments/{assessment.id}/authorization-files",
        headers=headers,
        json={},
    )
    assert missing_target.status_code == 422
    assert missing_target.json()["error"]["code"] == "authorization_target_required"

    assessment.target_base_url = "http://localhost:3000"
    await db.commit()
    bad_path = await client.post(
        f"/api/v1/assessments/{assessment.id}/authorization-files",
        headers=headers,
        json={"verification_path": "not-absolute"},
    )
    assert bad_path.status_code == 422
    assert bad_path.json()["error"]["code"] == "validation_error"


async def test_tokens_are_unique_per_target_and_user(
    client: AsyncClient, db: AsyncSession
) -> None:
    user, headers, first_assessment = await _setup(client, db)
    second_assessment = await create_assessment(
        db, user=user, name="Second target", target_base_url="http://localhost:3000"
    )
    first = await client.post(
        f"/api/v1/assessments/{first_assessment.id}/authorization-files",
        headers=headers,
        json={},
    )
    second = await client.post(
        f"/api/v1/assessments/{second_assessment.id}/authorization-files",
        headers=headers,
        json={},
    )
    assert first.status_code == 201
    assert second.status_code == 201
    assert first.json()["token"] != second.json()["token"]
    assert first.json()["created_by"] == user.id
    assert second.json()["created_by"] == user.id
