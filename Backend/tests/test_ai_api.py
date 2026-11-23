from __future__ import annotations

from app.core.config import get_settings
from app.db.enums import AIAnalysisStatus, ScopeKind, Severity
from app.db.models import AIAnalysis, Finding
from app.services.ai.base import ProviderError
from app.services.ai.manager import AIAnalysisManager, get_ai_manager
from app.services.ai.service import AIAnalysisService, RateLimiter
from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from tests.fakes import ScriptedProvider
from tests.utils import (
    add_scope,
    create_assessment,
    create_finding,
    create_user,
    login_headers,
)


async def _setup(
    client: AsyncClient,
    db: AsyncSession,
    *,
    email: str = "ai-api@example.test",
    with_finding: bool = True,
):
    user = await create_user(db, email=email)
    headers = await login_headers(client, email)
    assessment = await create_assessment(
        db,
        user=user,
        target_base_url="http://127.0.0.1:3000",
        authorized=True,
    )
    await add_scope(db, assessment, ScopeKind.HOST, "127.0.0.1")
    finding = await create_finding(db, assessment) if with_finding else None
    return user, headers, assessment, finding


async def test_analyze_finding_returns_both_advisory_functions(
    client: AsyncClient, db: AsyncSession
) -> None:
    user, headers, _, finding = await _setup(client, db)

    response = await client.post(
        f"/api/v1/findings/{finding.id}/analyze", headers=headers
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["finding_id"] == finding.id
    assert [item["function"] for item in body["analyses"]] == [
        "interpret",
        "remediate",
    ]
    assert all(item["status"] == "success" for item in body["analyses"])
    assert body["analyses"][0]["output"]["suggested_severity"] == "medium"
    assert body["analyses"][0]["sanitized_input"].startswith("FUNCTION: interpret")

    await db.refresh(finding)
    assert finding.ai_suggested_severity is Severity.MEDIUM
    assert finding.final_severity is None
    assert finding.tool_severity is Severity.HIGH

    listing = await client.get(
        f"/api/v1/findings/{finding.id}/ai-analyses", headers=headers
    )
    assert listing.status_code == 200
    rows = listing.json()
    assert len(rows) == 2
    assert {row["function"] for row in rows} == {"interpret", "remediate"}
    assert all(row["sanitized_input"] for row in rows)
    assert all(row["redaction_report"] is not None for row in rows)


async def test_analyze_unknown_finding_returns_404(
    client: AsyncClient, db: AsyncSession
) -> None:
    _, headers, _, _ = await _setup(client, db)
    response = await client.post("/api/v1/findings/9999/analyze", headers=headers)
    assert response.status_code == 404
    listing = await client.get("/api/v1/findings/9999/ai-analyses", headers=headers)
    assert listing.status_code == 404


async def test_bulk_analysis_filters_and_reports_progress(
    client: AsyncClient,
    db: AsyncSession,
    ai_manager: AIAnalysisManager,
) -> None:
    _, headers, assessment, _ = await _setup(
        client, db, with_finding=False
    )
    await create_finding(
        db,
        assessment,
        title="Critical injection",
        tool_severity=Severity.CRITICAL,
        parameter="id",
    )
    await create_finding(
        db,
        assessment,
        title="Medium exposure",
        tool_severity=Severity.MEDIUM,
        parameter="page",
    )
    await create_finding(
        db,
        assessment,
        title="Low disclosure",
        tool_severity=Severity.LOW,
        parameter="debug",
    )

    queued = await client.post(
        f"/api/v1/assessments/{assessment.id}/analyze",
        headers=headers,
        json={"only_unanalyzed": True, "min_severity": "high"},
    )
    assert queued.status_code == 202, queued.text
    body = queued.json()
    assert body["total"] == 1
    assert body["assessment_id"] == assessment.id
    await ai_manager.wait(body["job_id"])

    status_response = await client.get(
        f"/api/v1/assessments/{assessment.id}/ai-status", headers=headers
    )
    assert status_response.status_code == 200, status_response.text
    status_body = status_response.json()
    assert status_body["total_findings"] == 3
    assert status_body["findings_with_interpretation"] == 1
    assert status_body["findings_with_remediation"] == 1
    assert status_body["pending_findings"] == 2
    assert status_body["job"]["status"] == "completed"
    assert status_body["job"]["processed"] == 1
    assert status_body["job"]["failed"] == 0
    assert status_body["last_analyzed_at"] is not None

    second = await client.post(
        f"/api/v1/assessments/{assessment.id}/analyze",
        headers=headers,
        json={"only_unanalyzed": True},
    )
    assert second.status_code == 202, second.text
    await ai_manager.wait(second.json()["job_id"])
    final_status = (
        await client.get(
            f"/api/v1/assessments/{assessment.id}/ai-status", headers=headers
        )
    ).json()
    assert final_status["findings_with_interpretation"] == 3
    assert final_status["pending_findings"] == 0

    analyses = int(
        await db.scalar(
            select(func.count(AIAnalysis.id))
            .join(Finding, Finding.id == AIAnalysis.finding_id)
            .where(Finding.assessment_id == assessment.id)
        )
        or 0
    )
    assert analyses == 6

    no_matches = await client.post(
        f"/api/v1/assessments/{assessment.id}/analyze",
        headers=headers,
        json={"only_unanalyzed": True},
    )
    assert no_matches.status_code == 409
    assert "No findings match" in no_matches.json()["error"]["message"]


async def test_ai_status_without_jobs_is_empty(
    client: AsyncClient, db: AsyncSession
) -> None:
    _, headers, assessment, _ = await _setup(client, db)
    response = await client.get(
        f"/api/v1/assessments/{assessment.id}/ai-status", headers=headers
    )
    assert response.status_code == 200
    body = response.json()
    assert body["total_findings"] == 1
    assert body["findings_with_interpretation"] == 0
    assert body["pending_findings"] == 1
    assert body["job"] is None


async def test_provider_failure_returns_rows_and_keeps_final_fields_empty(
    client: AsyncClient,
    db: AsyncSession,
    app,
    session_factory,
) -> None:
    _, headers, _, finding = await _setup(
        client, db, email="ai-failure@example.test"
    )
    provider = ScriptedProvider(
        [ProviderError("provider unavailable"), ProviderError("provider unavailable")]
    )
    service = AIAnalysisService(
        get_settings(),
        provider,
        limiter=RateLimiter(100, 2),
        retry_base_seconds=0,
    )
    manager = AIAnalysisManager(
        session_factory, get_settings(), service=service
    )
    app.dependency_overrides[get_ai_manager] = lambda: manager
    try:
        response = await client.post(
            f"/api/v1/findings/{finding.id}/analyze", headers=headers
        )
        assert response.status_code == 200, response.text
        analyses = response.json()["analyses"]
        assert [item["status"] for item in analyses] == ["failed", "failed"]
        assert all(item["output"] is None for item in analyses)

        await db.refresh(finding)
        assert finding.ai_suggested_severity is None
        assert finding.final_severity is None
        rows = (
            (await db.execute(select(AIAnalysis).where(AIAnalysis.finding_id == finding.id)))
            .scalars()
            .all()
        )
        assert len(rows) == 2
        assert all(row.status is AIAnalysisStatus.FAILED for row in rows)
    finally:
        await manager.shutdown()
