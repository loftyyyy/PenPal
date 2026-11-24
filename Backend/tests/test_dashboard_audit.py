from __future__ import annotations

from datetime import timedelta

from app.db.base import utcnow
from app.db.enums import (
    AIAnalysisStatus,
    AIFunction,
    FindingCategory,
    ScanStatus,
    ScanTool,
    Severity,
    VerificationStatus,
)
from app.db.models import AIAnalysis, Scan
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from tests.utils import (
    create_assessment,
    create_finding,
    create_user,
    login_headers,
)


async def _setup(
    client: AsyncClient, db: AsyncSession, *, email: str = "dashboard@example.test"
):
    user = await create_user(db, email=email)
    headers = await login_headers(client, email)
    assessment = await create_assessment(db, user=user, authorized=True)
    return user, headers, assessment


async def test_dashboard_counts_basis_coverage_and_history(
    client: AsyncClient, db: AsyncSession
) -> None:
    user, headers, assessment = await _setup(client, db)
    injection = await create_finding(
        db,
        assessment,
        title="Pending high injection",
        tool_severity=Severity.HIGH,
        category=FindingCategory.INJECTION,
    )
    access = await create_finding(
        db,
        assessment,
        title="AI says critical",
        tool_severity=Severity.MEDIUM,
        category=FindingCategory.ACCESS_CONTROL,
        parameter="id",
    )
    access.ai_suggested_severity = Severity.CRITICAL
    confirmed = await create_finding(
        db,
        assessment,
        title="Confirmed injection",
        tool_severity=Severity.INFO,
        category=FindingCategory.INJECTION,
        parameter="search",
    )
    confirmed.verification_status = VerificationStatus.CONFIRMED
    confirmed.final_severity = Severity.HIGH
    false_positive = await create_finding(
        db,
        assessment,
        title="Rejected config issue",
        tool_severity=Severity.LOW,
        category=FindingCategory.SECURITY_CONFIGURATION,
        parameter="debug",
    )
    false_positive.verification_status = VerificationStatus.FALSE_POSITIVE
    false_positive.final_severity = None
    await db.commit()

    started = utcnow() - timedelta(seconds=12.5)
    scan = Scan(
        assessment_id=assessment.id,
        tool=ScanTool.ZAP,
        profile="baseline",
        target="http://127.0.0.1:3000/",
        status=ScanStatus.COMPLETED,
        progress=100,
        started_at=started,
        finished_at=started + timedelta(seconds=12.5),
        parameters={},
        created_by=user.id,
    )
    db.add(scan)
    db.add(
        AIAnalysis(
            finding_id=access.id,
            function=AIFunction.INTERPRET,
            provider="mock",
            model="mock-deterministic",
            prompt_version="test",
            input_hash="a" * 64,
            sanitized_input="FUNCTION: interpret",
            output={"suggested_severity": "critical"},
            status=AIAnalysisStatus.SUCCESS,
            redaction_report={"password": 1},
        )
    )
    await db.commit()

    response = await client.get(
        f"/api/v1/assessments/{assessment.id}/dashboard", headers=headers
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["total_findings"] == 4
    assert body["severity_counts"] == {
        "critical": 0,
        "high": 1,
        "medium": 0,
        "low": 0,
        "info": 0,
    }
    assert "Only confirmed findings contribute" in body["severity_basis"]
    assert body["verification_counts"] == {
        "pending": 2,
        "confirmed": 1,
        "false_positive": 1,
        "needs_retest": 0,
    }
    assert body["category_counts"] == {
        "injection": 2,
        "access_control": 1,
        "security_configuration": 1,
    }
    assert body["ai_coverage"] == {
        "analyzed": 1,
        "total": 4,
        "coverage_percent": 25.0,
    }
    assert body["scan_history"][0]["id"] == scan.id
    assert body["scan_history"][0]["tool"] == "zap"
    assert body["scan_history"][0]["duration_seconds"] == 12.5
    assert body["top_confirmed_findings"] == [
        {
            "id": confirmed.id,
            "title": "Confirmed injection",
            "final_severity": "high",
            "category": "injection",
            "affected_url": confirmed.affected_url,
        }
    ]
    assert body["last_updated_at"] is not None
    assert injection.id != confirmed.id


async def test_dashboard_for_empty_assessment(
    client: AsyncClient, db: AsyncSession
) -> None:
    _, headers, assessment = await _setup(
        client, db, email="dashboard-empty@example.test"
    )
    response = await client.get(
        f"/api/v1/assessments/{assessment.id}/dashboard", headers=headers
    )
    assert response.status_code == 200
    body = response.json()
    assert body["total_findings"] == 0
    assert body["severity_counts"] == {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }
    assert body["verification_counts"] == {
        "pending": 0,
        "confirmed": 0,
        "false_positive": 0,
        "needs_retest": 0,
    }
    assert body["category_counts"] == {}
    assert body["scan_history"] == []
    assert body["ai_coverage"] == {
        "analyzed": 0,
        "total": 0,
        "coverage_percent": 0.0,
    }
    assert body["top_confirmed_findings"] == []
    assert body["last_updated_at"] is not None


async def test_audit_log_is_paginated_newest_first(
    client: AsyncClient, db: AsyncSession
) -> None:
    _, headers, assessment = await _setup(client, db)
    created = await client.post(
        f"/api/v1/assessments/{assessment.id}/findings",
        headers=headers,
        json={
            "title": "Audit trail finding",
            "severity": "medium",
            "category": "injection",
        },
    )
    assert created.status_code == 201
    finding_id = created.json()["id"]
    note = await client.post(
        f"/api/v1/findings/{finding_id}/evidence",
        headers=headers,
        data={"note": "Audit trail note."},
    )
    assert note.status_code == 201
    verified = await client.patch(
        f"/api/v1/findings/{finding_id}/verify",
        headers=headers,
        json={
            "decision": "confirmed",
            "final_severity": "medium",
            "final_remediation": "Fix it.",
        },
    )
    assert verified.status_code == 200

    response = await client.get(
        f"/api/v1/assessments/{assessment.id}/audit-log", headers=headers
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["total"] >= 3
    actions = [item["action"] for item in body["items"]]
    assert "finding.created" in actions
    assert "evidence.added" in actions
    assert "finding.verified" in actions
    assert actions[0] == "finding.verified"
    ids = [item["id"] for item in body["items"]]
    assert ids == sorted(ids, reverse=True)
    assert body["items"][0]["assessment_id"] == assessment.id

    paged = await client.get(
        f"/api/v1/assessments/{assessment.id}/audit-log",
        headers=headers,
        params={"page": 1, "page_size": 2},
    )
    assert paged.status_code == 200
    assert paged.json()["total"] == body["total"]
    assert len(paged.json()["items"]) == 2

    unknown = await client.get("/api/v1/assessments/9999/audit-log", headers=headers)
    assert unknown.status_code == 404
