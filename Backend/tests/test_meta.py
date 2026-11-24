from __future__ import annotations

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from tests.utils import create_user, login_headers


async def test_severity_matrix_metadata_is_authenticated(
    client: AsyncClient, db: AsyncSession
) -> None:
    unauthenticated = await client.get("/api/v1/meta/severity-matrix")
    assert unauthenticated.status_code == 401

    await create_user(db, email="meta@example.test")
    headers = await login_headers(client, "meta@example.test")
    response = await client.get("/api/v1/meta/severity-matrix", headers=headers)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["likelihood"]["minimum"] == 1
    assert body["likelihood"]["maximum"] == 5
    assert body["impact"]["labels"]["5"] == "severe"
    assert body["formula"] == "score = likelihood x impact"
    assert body["final_severity_source"] == "server"
    thresholds = {item["severity"]: item for item in body["thresholds"]}
    assert thresholds["critical"] == {
        "min_score": 20,
        "max_score": 25,
        "severity": "critical",
    }
    assert thresholds["high"]["min_score"] == 12
    assert thresholds["medium"]["min_score"] == 6
    assert thresholds["low"]["min_score"] == 3
    assert thresholds["info"]["min_score"] == 1
