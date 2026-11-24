from __future__ import annotations

from app.db.enums import (
    AIAnalysisStatus,
    AIFunction,
    FindingCategory,
    ScopeKind,
    Severity,
    SummaryStatus,
    VerificationStatus,
)
from app.db.models import AIAnalysis, AssessmentSummary
from app.services.ai.mock import MockProvider
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from tests.utils import add_scope, create_assessment, create_finding, create_user, login_headers


async def _setup(
    client: AsyncClient, db: AsyncSession, *, email: str = "summary@example.test"
):
    user = await create_user(db, email=email)
    headers = await login_headers(client, email)
    assessment = await create_assessment(
        db, user=user, target_base_url="http://127.0.0.1:3000", authorized=True
    )
    await add_scope(db, assessment, ScopeKind.HOST, "127.0.0.1")
    return user, headers, assessment


async def test_summary_generate_edit_approve_and_use_approved_only(
    client: AsyncClient,
    db: AsyncSession,
    ai_provider: MockProvider,
) -> None:
    user, headers, assessment = await _setup(client, db)
    confirmed = await create_finding(
        db,
        assessment,
        title="Confirmed injection",
        category=FindingCategory.INJECTION,
        tool_severity=Severity.HIGH,
    )
    confirmed.verification_status = VerificationStatus.CONFIRMED
    confirmed.final_severity = Severity.CRITICAL
    confirmed.likelihood = 5
    confirmed.impact = 5
    confirmed.final_remediation = "Use parameterised queries.\nSecond line omitted."
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

    generated = await client.post(
        f"/api/v1/assessments/{assessment.id}/summary/generate", headers=headers
    )
    assert generated.status_code == 200, generated.text
    body = generated.json()
    assert body["status"] == "draft"
    assert body["provider"] == "mock"
    assert body["overall_risk"] == "critical"
    assert body["text"]
    assert body["edited_text"] is None

    assert len(ai_provider.calls) == 1
    seen = ai_provider.calls[0]["user"]
    assert "Confirmed injection" in seen
    assert "PENDING-SECRET title must not be summarized" not in seen
    assert "Second line omitted" not in seen
    assert pending.id != confirmed.id

    analysis = await db.scalar(
        select(AIAnalysis).where(
            AIAnalysis.assessment_id == assessment.id,
            AIAnalysis.function == AIFunction.SUMMARY,
        )
    )
    assert analysis is not None
    assert analysis.status is AIAnalysisStatus.SUCCESS
    summary_row = await db.get(AssessmentSummary, body["id"])
    assert summary_row is not None
    assert summary_row.status is SummaryStatus.DRAFT
    assert summary_row.ai_analysis_id == analysis.id

    bundle = await client.get(
        f"/api/v1/assessments/{assessment.id}/summary", headers=headers
    )
    assert bundle.status_code == 200
    assert bundle.json()["latest"]["id"] == body["id"]
    assert len(bundle.json()["history"]) == 1

    edited = await client.patch(
        f"/api/v1/summaries/{body['id']}",
        headers=headers,
        json={"text": "Assessor-edited summary text."},
    )
    assert edited.status_code == 200
    assert edited.json()["text"] == "Assessor-edited summary text."
    assert edited.json()["status"] == "draft"

    approved = await client.post(
        f"/api/v1/summaries/{body['id']}/approve", headers=headers
    )
    assert approved.status_code == 200
    assert approved.json()["status"] == "approved"
    assert approved.json()["approved_by"] == user.id
    assert approved.json()["approved_at"] is not None

    dashboard = await client.get(
        f"/api/v1/assessments/{assessment.id}/dashboard", headers=headers
    )
    assert dashboard.status_code == 200
    assert dashboard.json()["ai_summary"]["id"] == body["id"]
    assert dashboard.json()["ai_summary"]["text"] == "Assessor-edited summary text."

    report = await client.post(
        f"/api/v1/assessments/{assessment.id}/reports",
        headers=headers,
        json={"format": "html"},
    )
    assert report.status_code == 201, report.text
    download = await client.get(
        f"/api/v1/reports/{report.json()['id']}/download", headers=headers
    )
    assert "Approved assessment summary" in download.text
    assert "Assessor-edited summary text." in download.text

    draft_after_approval = await client.patch(
        f"/api/v1/summaries/{body['id']}",
        headers=headers,
        json={"text": "Edited after approval."},
    )
    assert draft_after_approval.status_code == 200
    assert draft_after_approval.json()["status"] == "draft"
    assert draft_after_approval.json()["approved_by"] is None


async def test_new_approval_supersedes_previous_and_draft_is_appendix_only(
    client: AsyncClient, db: AsyncSession
) -> None:
    _, headers, assessment = await _setup(
        client, db, email="summary-supersede@example.test"
    )
    finding = await create_finding(db, assessment, title="Confirmed finding")
    finding.verification_status = VerificationStatus.CONFIRMED
    finding.final_severity = Severity.HIGH
    await db.commit()

    first = (
        await client.post(
            f"/api/v1/assessments/{assessment.id}/summary/generate",
            headers=headers,
        )
    ).json()
    await client.post(f"/api/v1/summaries/{first['id']}/approve", headers=headers)

    second = (
        await client.post(
            f"/api/v1/assessments/{assessment.id}/summary/generate",
            headers=headers,
        )
    ).json()
    await client.post(f"/api/v1/summaries/{second['id']}/approve", headers=headers)

    rows = (
        (
            await db.execute(
                select(AssessmentSummary)
                .where(AssessmentSummary.assessment_id == assessment.id)
                .order_by(AssessmentSummary.id)
            )
        )
        .scalars()
        .all()
    )
    assert [row.status for row in rows] == [
        SummaryStatus.SUPERSEDED,
        SummaryStatus.APPROVED,
    ]

    third = (
        await client.post(
            f"/api/v1/assessments/{assessment.id}/summary/generate",
            headers=headers,
        )
    ).json()
    assert third["status"] == "draft"
    report = await client.post(
        f"/api/v1/assessments/{assessment.id}/reports",
        headers=headers,
        json={"format": "html"},
    )
    html = (
        await client.get(
            f"/api/v1/reports/{report.json()['id']}/download", headers=headers
        )
    ).text
    assert "Approved assessment summary" in html
    assert "UNVERIFIED AI summary draft" in html


async def test_no_confirmed_findings_skips_ai(
    client: AsyncClient, db: AsyncSession, ai_provider: MockProvider
) -> None:
    _, headers, assessment = await _setup(
        client, db, email="summary-empty@example.test"
    )
    await create_finding(db, assessment, title="Only pending")

    response = await client.post(
        f"/api/v1/assessments/{assessment.id}/summary/generate", headers=headers
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["provider"] == "deterministic"
    assert body["overall_risk"] == "info"
    assert "No findings were confirmed" in body["text"]
    assert ai_provider.calls == []


async def test_summary_provider_failure_returns_502(
    client: AsyncClient,
    db: AsyncSession,
    app,
    session_factory,
) -> None:
    from app.core.config import get_settings
    from app.services.ai.base import ProviderError
    from app.services.ai.manager import AIAnalysisManager, get_ai_manager
    from app.services.ai.service import AIAnalysisService, RateLimiter
    from tests.fakes import ScriptedProvider

    _, headers, assessment = await _setup(
        client, db, email="summary-fail@example.test"
    )
    finding = await create_finding(db, assessment, title="Summary failure finding")
    finding.verification_status = VerificationStatus.CONFIRMED
    finding.final_severity = Severity.HIGH
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
            f"/api/v1/assessments/{assessment.id}/summary/generate",
            headers=headers,
        )
        assert response.status_code == 502
        assert response.json()["error"]["code"] == "summary_generation_failed"
        count = await db.scalar(
            select(AssessmentSummary).where(
                AssessmentSummary.assessment_id == assessment.id
            )
        )
        assert count is None
    finally:
        await manager.shutdown()
