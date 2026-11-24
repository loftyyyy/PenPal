from __future__ import annotations

from app.db.enums import (
    AIAnalysisStatus,
    AIFunction,
    FindingCategory,
    ScopeKind,
    Severity,
    VerificationStatus,
)
from app.db.models import AIAnalysis, AuditLog
from app.services.ai.manager import AIAnalysisManager
from app.services.ai.mock import MockProvider
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from tests.utils import add_scope, create_assessment, create_finding, create_user, login_headers


async def _setup(
    client: AsyncClient, db: AsyncSession, *, email: str = "ai-summary@example.test"
):
    user = await create_user(db, email=email)
    headers = await login_headers(client, email)
    assessment = await create_assessment(
        db, user=user, target_base_url="http://127.0.0.1:3000", authorized=True
    )
    await add_scope(db, assessment, ScopeKind.HOST, "127.0.0.1")
    return user, headers, assessment


async def test_summary_uses_only_confirmed_findings_and_is_stored(
    client: AsyncClient,
    db: AsyncSession,
    ai_provider: MockProvider,
) -> None:
    _, headers, assessment = await _setup(client, db)
    confirmed = await create_finding(
        db,
        assessment,
        title="Confirmed injection",
        category=FindingCategory.INJECTION,
        tool_severity=Severity.HIGH,
    )
    confirmed.verification_status = VerificationStatus.CONFIRMED
    confirmed.final_severity = Severity.CRITICAL
    confirmed.final_remediation = "Use parameterised queries."
    await db.commit()
    pending = await create_finding(
        db,
        assessment,
        title="PENDING-SECRET title must not be summarized",
        category=FindingCategory.ACCESS_CONTROL,
        tool_severity=Severity.MEDIUM,
        parameter="pending",
    )
    await db.commit()

    response = await client.post(
        f"/api/v1/assessments/{assessment.id}/analyze-summary", headers=headers
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["function"] == "summary"
    assert body["finding_id"] is None
    assert body["assessment_id"] == assessment.id
    assert body["status"] == "success"
    assert body["output"]["executive_summary"]
    assert body["output"]["key_risks"]
    assert body["output"]["overall_risk"] == "high"

    assert len(ai_provider.calls) == 1
    seen = ai_provider.calls[0]["user"]
    assert "Confirmed injection" in seen
    assert "PENDING-SECRET title must not be summarized" not in seen
    assert pending.id != confirmed.id

    row = await db.scalar(
        select(AIAnalysis).where(
            AIAnalysis.assessment_id == assessment.id,
            AIAnalysis.function == AIFunction.SUMMARY,
        )
    )
    assert row is not None
    assert row.finding_id is None
    assert row.status is AIAnalysisStatus.SUCCESS
    assert row.output is not None

    audit = (
        await db.execute(
            select(AuditLog).where(
                AuditLog.action == "ai.analyzed",
                AuditLog.entity_type == "assessment",
            )
        )
    ).scalars()
    assert len(list(audit)) == 1

    latest = await client.get(
        f"/api/v1/assessments/{assessment.id}/ai-summary", headers=headers
    )
    assert latest.status_code == 200
    assert latest.json()["id"] == row.id

    dashboard = await client.get(
        f"/api/v1/assessments/{assessment.id}/dashboard", headers=headers
    )
    assert dashboard.status_code == 200
    assert dashboard.json()["ai_summary"]["id"] == row.id

    report = await client.post(
        f"/api/v1/assessments/{assessment.id}/reports",
        headers=headers,
        json={"format": "html"},
    )
    assert report.status_code == 201, report.text
    download = await client.get(
        f"/api/v1/reports/{report.json()['id']}/download", headers=headers
    )
    assert "Mock assessment summary" in download.text


async def test_summary_requires_confirmed_findings(
    client: AsyncClient, db: AsyncSession
) -> None:
    _, headers, assessment = await _setup(
        client, db, email="ai-summary-empty@example.test"
    )
    await create_finding(
        db,
        assessment,
        title="Only pending",
        category=FindingCategory.INJECTION,
    )
    response = await client.post(
        f"/api/v1/assessments/{assessment.id}/analyze-summary", headers=headers
    )
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "no_confirmed_findings"

    latest = await client.get(
        f"/api/v1/assessments/{assessment.id}/ai-summary", headers=headers
    )
    assert latest.status_code == 404


async def test_summary_failure_is_recorded_without_confirmed_side_effects(
    client: AsyncClient,
    db: AsyncSession,
    app,
    session_factory,
) -> None:
    from app.core.config import get_settings
    from app.services.ai.base import ProviderError
    from app.services.ai.manager import get_ai_manager
    from app.services.ai.service import AIAnalysisService, RateLimiter
    from tests.fakes import ScriptedProvider


    user, headers, assessment = await _setup(
        client, db, email="ai-summary-fail@example.test"
    )
    confirmed = await create_finding(db, assessment, title="Summary failure finding")
    confirmed.verification_status = VerificationStatus.CONFIRMED
    confirmed.final_severity = Severity.HIGH
    await db.commit()

    provider = ScriptedProvider([ProviderError("provider unavailable")])
    service = AIAnalysisService(
        get_settings(),
        provider,
        limiter=RateLimiter(100, 2),
        retry_base_seconds=0,
    )
    manager = AIAnalysisManager(session_factory, get_settings(), service=service)
    app.dependency_overrides[get_ai_manager] = lambda: manager
    try:
        response = await client.post(
            f"/api/v1/assessments/{assessment.id}/analyze-summary",
            headers=headers,
        )
        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "failed"
        assert body["output"] is None
        assert "provider unavailable" in body["error"]
        await db.refresh(confirmed)
        assert confirmed.final_severity is not None
        assert confirmed.verification_status is VerificationStatus.CONFIRMED
    finally:
        await manager.shutdown()
