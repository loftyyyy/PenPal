from __future__ import annotations

from pathlib import Path

from app.core.config import get_settings
from app.db.base import utcnow
from app.db.enums import (
    AIAnalysisStatus,
    AIFunction,
    EvidenceType,
    FindingCategory,
    ReportFormat,
    ReportStatus,
    ScanStatus,
    ScanTool,
    ScopeKind,
    Severity,
    VerificationStatus,
)
from app.db.models import AIAnalysis, AuditLog, Evidence, Report, Scan
from app.services import report_builder
from app.services.storage import resolve_data_path
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from tests.utils import (
    add_evidence,
    add_scope,
    create_assessment,
    create_finding,
    create_user,
    login_headers,
)


async def _setup(
    client: AsyncClient, db: AsyncSession, *, email: str = "reports@example.test"
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
    await add_scope(
        db,
        assessment,
        ScopeKind.URL_PREFIX,
        "http://127.0.0.1:3000/admin",
        in_scope=False,
    )
    return user, headers, assessment


async def _confirmed_finding(db: AsyncSession, assessment, **kwargs):
    final_severity = kwargs.pop("final_severity", Severity.HIGH)
    final_remediation = kwargs.pop(
        "final_remediation", "Apply the vendor fix and re-test."
    )
    finding = await create_finding(db, assessment, **kwargs)
    finding.verification_status = VerificationStatus.CONFIRMED
    finding.final_severity = final_severity
    finding.final_remediation = final_remediation
    finding.verified_by = assessment.created_by
    finding.verified_at = utcnow()
    await db.commit()
    await db.refresh(finding)
    return finding


async def test_html_report_contains_only_confirmed_escaped_findings(
    client: AsyncClient, db: AsyncSession
) -> None:
    user, headers, assessment = await _setup(client, db)
    confirmed = await _confirmed_finding(
        db,
        assessment,
        title='<script>alert("confirmed")</script> SQL injection',
        description='Evidence includes <img src=x onerror=alert(1)> here.',
        category=FindingCategory.INJECTION,
        parameter="q",
        final_severity=Severity.CRITICAL,
    )
    pending = await create_finding(
        db,
        assessment,
        title="PENDING-ONLY finding must not appear",
        category=FindingCategory.ACCESS_CONTROL,
        parameter="pending",
    )
    rejected = await create_finding(
        db,
        assessment,
        title="Rejected finding",
        category=FindingCategory.SESSION_MANAGEMENT,
        parameter="rejected",
    )
    rejected.verification_status = VerificationStatus.FALSE_POSITIVE
    rejected.rejection_reason = "A static demo page, not a real issue."
    retest = await create_finding(
        db,
        assessment,
        title="Needs retest finding",
        category=FindingCategory.SECURITY_CONFIGURATION,
        parameter="retest",
    )
    retest.verification_status = VerificationStatus.NEEDS_RETEST
    await db.commit()

    await add_evidence(
        db,
        confirmed,
        "REQUEST\nGET /search?q=<script>alert(1)</script>\n\n"
        + ("A" * 5000),
        user=user,
    )
    file_evidence = Evidence(
        finding_id=confirmed.id,
        type=EvidenceType.FILE,
        file_path=f"uploads/{assessment.id}/{confirmed.id}/screenshot.png",
        sha256="f" * 64,
        created_by=user.id,
    )
    db.add(file_evidence)
    db.add(
        AIAnalysis(
            finding_id=confirmed.id,
            function=AIFunction.INTERPRET,
            provider="mock",
            model="mock-deterministic",
            prompt_version="test",
            input_hash="b" * 64,
            sanitized_input="FUNCTION: interpret",
            output={"suggested_severity": "critical"},
            status=AIAnalysisStatus.SUCCESS,
            redaction_report={"password": 2, "cookie_header": 1},
        )
    )
    started = utcnow()
    db.add(
        Scan(
            assessment_id=assessment.id,
            tool=ScanTool.NMAP,
            profile="quick",
            target="127.0.0.1",
            status=ScanStatus.COMPLETED,
            progress=100,
            started_at=started,
            finished_at=started,
            tool_version="7.95",
            parameters={},
            created_by=user.id,
        )
    )
    await db.commit()

    response = await client.post(
        f"/api/v1/assessments/{assessment.id}/reports",
        headers=headers,
        json={"format": "html"},
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["format"] == "html"
    assert body["status"] == "ready"
    assert body["has_file"] is True
    assert len(body["sha256"]) == 64
    assert body["summary_counts"]["confirmed"] == 1
    assert body["summary_counts"]["critical"] == 1
    assert body["summary_counts"]["false_positive"] == 1
    assert body["summary_counts"]["needs_retest"] == 1

    path = resolve_data_path(
        get_settings(), f"reports/{assessment.id}/report-{body['id']}.html"
    )
    assert path.is_file()
    html = path.read_text(encoding="utf-8")
    assert "confirmed" in html
    assert "UNVERIFIED: PENDING-ONLY finding must not appear" in html
    assert "Rejected finding" not in html
    assert "UNVERIFIED: Needs retest finding" in html
    assert "&lt;script&gt;alert" in html
    assert '<script>alert("confirmed")</script>' not in html
    assert "&lt;img src=x onerror=alert(1)&gt;" in html
    assert "[truncated for report]" in html
    assert "screenshot.png" in html
    assert "mock-deterministic" in html
    assert "password=2" in html
    assert "cookie_header=1" in html
    assert "127.0.0.1" in html
    assert "7.95" in html
    assert "False positive" in html
    assert "Needs retest" in html

    import hashlib

    assert hashlib.sha256(path.read_bytes()).hexdigest() == body["sha256"]

    audit_actions = (
        (await db.execute(select(AuditLog.action).where(AuditLog.action == "report.generated")))
        .scalars()
        .all()
    )
    assert audit_actions == ["report.generated"]
    assert pending.id != confirmed.id

    listing = await client.get(
        f"/api/v1/assessments/{assessment.id}/reports", headers=headers
    )
    assert listing.status_code == 200
    assert listing.json()["total"] == 1

    download = await client.get(
        f"/api/v1/reports/{body['id']}/download", headers=headers
    )
    assert download.status_code == 200
    assert download.content == path.read_bytes()
    assert download.headers["content-type"].startswith("text/html")
    assert "attachment" in download.headers["content-disposition"]


async def test_pdf_report_success_with_renderer(
    client: AsyncClient, db: AsyncSession, monkeypatch
) -> None:
    _, headers, assessment = await _setup(client, db, email="reports-pdf@example.test")
    await _confirmed_finding(db, assessment, title="PDF finding")

    def fake_pdf(html: str, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"%PDF-1.7\nfake report body\n")

    monkeypatch.setattr(report_builder, "_render_pdf", fake_pdf)
    response = await client.post(
        f"/api/v1/assessments/{assessment.id}/reports",
        headers=headers,
        json={"format": "pdf"},
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["format"] == "pdf"
    assert body["status"] == "ready"
    assert body["error"] is None
    assert "pdf_fallback" not in body["summary_counts"]

    download = await client.get(
        f"/api/v1/reports/{body['id']}/download", headers=headers
    )
    assert download.status_code == 200
    assert download.content.startswith(b"%PDF-1.7")
    assert download.headers["content-type"].startswith("application/pdf")


async def test_pdf_failure_keeps_html_report(
    client: AsyncClient, db: AsyncSession, monkeypatch
) -> None:
    _, headers, assessment = await _setup(
        client, db, email="reports-pdf-fail@example.test"
    )
    await _confirmed_finding(db, assessment, title="Fallback finding")

    def broken_pdf(html: str, path: Path) -> None:
        raise RuntimeError("pango missing")

    monkeypatch.setattr(report_builder, "_render_pdf", broken_pdf)
    response = await client.post(
        f"/api/v1/assessments/{assessment.id}/reports",
        headers=headers,
        json={"format": "pdf"},
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["format"] == "html"
    assert body["status"] == "ready"
    assert "PDF rendering failed" in body["error"]
    assert body["summary_counts"]["pdf_fallback"] is True
    assert body["has_file"] is True

    download = await client.get(
        f"/api/v1/reports/{body['id']}/download", headers=headers
    )
    assert download.status_code == 200
    assert download.headers["content-type"].startswith("text/html")
    assert b"Fallback finding" in download.content


async def test_report_download_requires_ready_file(
    client: AsyncClient, db: AsyncSession
) -> None:
    user, headers, assessment = await _setup(
        client, db, email="reports-not-ready@example.test"
    )
    pending = Report(
        assessment_id=assessment.id,
        format=ReportFormat.HTML,
        status=ReportStatus.PENDING,
        generated_by=user.id,
        summary_counts={},
    )
    db.add(pending)
    await db.commit()
    await db.refresh(pending)

    response = await client.get(
        f"/api/v1/reports/{pending.id}/download", headers=headers
    )
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "report_not_ready"

    missing = await client.get("/api/v1/reports/9999/download", headers=headers)
    assert missing.status_code == 404

    unknown_assessment = await client.post(
        "/api/v1/assessments/9999/reports",
        headers=headers,
        json={"format": "html"},
    )
    assert unknown_assessment.status_code == 404


async def test_report_for_unknown_filename_is_not_exposed(
    client: AsyncClient, db: AsyncSession
) -> None:
    user, headers, assessment = await _setup(
        client, db, email="reports-unsafe@example.test"
    )
    report = Report(
        assessment_id=assessment.id,
        format=ReportFormat.HTML,
        status=ReportStatus.READY,
        file_path="../outside.html",
        generated_by=user.id,
        summary_counts={},
    )
    db.add(report)
    await db.commit()
    await db.refresh(report)

    response = await client.get(
        f"/api/v1/reports/{report.id}/download", headers=headers
    )
    assert response.status_code == 404
