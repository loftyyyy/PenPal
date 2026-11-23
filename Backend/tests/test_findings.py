from __future__ import annotations

from app.core.config import get_settings
from app.db.enums import (
    FindingCategory,
    FindingSource,
    Severity,
    VerificationStatus,
)
from app.db.models import AuditLog, Evidence
from app.services.storage import resolve_data_path
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from tests.utils import (
    create_assessment,
    create_finding,
    create_user,
    login_headers,
)


async def _setup(
    client: AsyncClient, db: AsyncSession, *, email: str = "findings@example.test"
):
    user = await create_user(db, email=email)
    headers = await login_headers(client, email)
    assessment = await create_assessment(db, user=user, authorized=True)
    return user, headers, assessment


async def test_list_findings_filters_sorting_and_pagination(
    client: AsyncClient, db: AsyncSession
) -> None:
    user, headers, assessment = await _setup(client, db)
    first = await create_finding(
        db,
        assessment,
        title="SQL injection in search",
        tool_severity=Severity.HIGH,
        category=FindingCategory.INJECTION,
        affected_url="http://127.0.0.1:3000/search?q=x",
    )
    second = await create_finding(
        db,
        assessment,
        title="Missing security header",
        tool_severity=Severity.LOW,
        category=FindingCategory.SECURITY_CONFIGURATION,
        source=FindingSource.ZAP,
        affected_url="http://127.0.0.1:3000/",
    )
    manual = await create_finding(
        db,
        assessment,
        title="Manual weak logout",
        tool_severity=Severity.INFO,
        category=FindingCategory.SESSION_MANAGEMENT,
        source=FindingSource.MANUAL,
        parameter="",
    )
    manual.verification_status = VerificationStatus.CONFIRMED
    manual.final_severity = Severity.CRITICAL
    await db.commit()

    response = await client.get(
        f"/api/v1/assessments/{assessment.id}/findings", headers=headers
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["total"] == 3
    assert body["page"] == 1
    assert body["page_size"] == 20
    assert {item["id"] for item in body["items"]} == {
        first.id,
        second.id,
        manual.id,
    }
    assert "raw" not in body["items"][0]

    by_severity = (
        await client.get(
            f"/api/v1/assessments/{assessment.id}/findings",
            headers=headers,
            params={"severity": "critical"},
        )
    ).json()
    assert by_severity["total"] == 1
    assert by_severity["items"][0]["id"] == manual.id

    by_status = (
        await client.get(
            f"/api/v1/assessments/{assessment.id}/findings",
            headers=headers,
            params={"status": "confirmed"},
        )
    ).json()
    assert by_status["total"] == 1

    by_category = (
        await client.get(
            f"/api/v1/assessments/{assessment.id}/findings",
            headers=headers,
            params={"category": "injection"},
        )
    ).json()
    assert by_category["total"] == 1
    assert by_category["items"][0]["id"] == first.id

    by_source = (
        await client.get(
            f"/api/v1/assessments/{assessment.id}/findings",
            headers=headers,
            params={"source": "manual"},
        )
    ).json()
    assert by_source["total"] == 1
    assert by_source["items"][0]["id"] == manual.id

    searched = (
        await client.get(
            f"/api/v1/assessments/{assessment.id}/findings",
            headers=headers,
            params={"q": "weak logout"},
        )
    ).json()
    assert searched["total"] == 1
    assert searched["items"][0]["id"] == manual.id

    severity_sorted = (
        await client.get(
            f"/api/v1/assessments/{assessment.id}/findings",
            headers=headers,
            params={"sort": "severity", "order": "desc"},
        )
    ).json()
    assert severity_sorted["items"][0]["id"] == manual.id

    paged = (
        await client.get(
            f"/api/v1/assessments/{assessment.id}/findings",
            headers=headers,
            params={"page": 2, "page_size": 2},
        )
    ).json()
    assert paged["total"] == 3
    assert len(paged["items"]) == 1

    invalid = await client.get(
        f"/api/v1/assessments/{assessment.id}/findings",
        headers=headers,
        params={"severity": "urgent"},
    )
    assert invalid.status_code == 422
    assert invalid.json()["error"]["code"] == "validation_error"


async def test_finding_detail_and_unknown(client: AsyncClient, db: AsyncSession) -> None:
    _, headers, assessment = await _setup(client, db)
    finding = await create_finding(db, assessment, raw={"pluginId": "40018"})

    detail = await client.get(f"/api/v1/findings/{finding.id}", headers=headers)
    assert detail.status_code == 200
    assert detail.json()["raw"] == {"pluginId": "40018"}
    assert detail.json()["verification_status"] == "pending"

    missing = await client.get("/api/v1/findings/99999", headers=headers)
    assert missing.status_code == 404


async def test_manual_finding_creation_and_duplicate_guard(
    client: AsyncClient, db: AsyncSession
) -> None:
    user, headers, assessment = await _setup(client, db)
    payload = {
        "title": "Business logic bypass in checkout",
        "description": "A negative quantity increases store credit.",
        "category": "business_logic",
        "severity": "high",
        "affected_url": "http://127.0.0.1:3000/checkout",
        "http_method": "post",
        "parameter": "quantity",
        "cwe": "CWE-840",
    }
    created = await client.post(
        f"/api/v1/assessments/{assessment.id}/findings",
        headers=headers,
        json=payload,
    )
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["source"] == "manual"
    assert body["tool_severity"] == "high"
    assert body["category"] == "business_logic"
    assert body["verification_status"] == "pending"
    assert body["final_severity"] is None
    assert body["verified_by"] is None
    assert body["http_method"] == "POST"
    assert body["seen_count"] == 1
    assert body["raw"]["manual"] is True

    actions = (
        (await db.execute(select(AuditLog.action).where(AuditLog.action == "finding.created")))
        .scalars()
        .all()
    )
    assert len(actions) == 1

    duplicate = await client.post(
        f"/api/v1/assessments/{assessment.id}/findings",
        headers=headers,
        json=payload,
    )
    assert duplicate.status_code == 409
    assert "already exists" in duplicate.json()["error"]["message"]

    blank = await client.post(
        f"/api/v1/assessments/{assessment.id}/findings",
        headers=headers,
        json={**payload, "title": "   "},
    )
    assert blank.status_code == 422

    bad_severity = await client.post(
        f"/api/v1/assessments/{assessment.id}/findings",
        headers=headers,
        json={**payload, "title": "Other", "severity": "urgent"},
    )
    assert bad_severity.status_code == 422


async def test_verify_rules_and_audit_history(
    client: AsyncClient, db: AsyncSession
) -> None:
    user, headers, assessment = await _setup(client, db)
    finding = await create_finding(
        db, assessment, tool_severity=Severity.HIGH, title="Verify me"
    )

    short_reason = await client.patch(
        f"/api/v1/findings/{finding.id}/verify",
        headers=headers,
        json={"decision": "false_positive", "reason": "false"},
    )
    assert short_reason.status_code == 422
    assert "at least 10" in short_reason.json()["error"]["message"]

    rejected = await client.patch(
        f"/api/v1/findings/{finding.id}/verify",
        headers=headers,
        json={
            "decision": "false_positive",
            "reason": "The endpoint is a static demo page.",
        },
    )
    assert rejected.status_code == 200, rejected.text
    assert rejected.json()["verification_status"] == "false_positive"
    assert rejected.json()["rejection_reason"] == "The endpoint is a static demo page."
    assert rejected.json()["final_severity"] is None
    assert rejected.json()["verified_by"] == user.id

    confirmed = await client.patch(
        f"/api/v1/findings/{finding.id}/verify",
        headers=headers,
        json={"decision": "confirmed", "final_remediation": "Escape output."},
    )
    assert confirmed.status_code == 200
    body = confirmed.json()
    assert body["verification_status"] == "confirmed"
    assert body["final_severity"] == "high"
    assert body["final_remediation"] == "Escape output."
    assert body["rejection_reason"] is None

    changed = await client.patch(
        f"/api/v1/findings/{finding.id}/verify",
        headers=headers,
        json={
            "decision": "confirmed",
            "final_severity": "critical",
            "final_remediation": "Use context-aware escaping.",
        },
    )
    assert changed.status_code == 200
    assert changed.json()["final_severity"] == "critical"

    needs_retest = await client.patch(
        f"/api/v1/findings/{finding.id}/verify",
        headers=headers,
        json={
            "decision": "needs_retest",
            "reason": "Retest after the WAF change.",
            "final_severity": "medium",
        },
    )
    assert needs_retest.status_code == 200
    assert needs_retest.json()["verification_status"] == "needs_retest"
    assert needs_retest.json()["final_severity"] == "medium"

    rows = (
        (
            await db.execute(
                select(AuditLog)
                .where(AuditLog.action == "finding.verified")
                .order_by(AuditLog.id)
            )
        )
        .scalars()
        .all()
    )
    assert len(rows) == 4
    assert rows[1].details["previous"]["verification_status"] == "false_positive"
    assert rows[1].details["new"]["verification_status"] == "confirmed"
    assert rows[1].details["severity_defaulted"] is True
    assert rows[2].details["severity_defaulted"] is False


async def test_confirmed_without_any_severity_is_rejected(
    client: AsyncClient, db: AsyncSession
) -> None:
    _, headers, assessment = await _setup(client, db)
    finding = await create_finding(db, assessment)
    finding.tool_severity = None
    await db.commit()

    response = await client.patch(
        f"/api/v1/findings/{finding.id}/verify",
        headers=headers,
        json={"decision": "confirmed"},
    )
    assert response.status_code == 422
    assert "final_severity" in response.json()["error"]["message"]


async def test_ai_analysis_never_overwrites_verified_fields(
    client: AsyncClient, db: AsyncSession
) -> None:
    _, headers, assessment = await _setup(client, db)
    finding = await create_finding(
        db, assessment, tool_severity=Severity.HIGH, title="AI must not decide"
    )
    verified = await client.patch(
        f"/api/v1/findings/{finding.id}/verify",
        headers=headers,
        json={
            "decision": "confirmed",
            "final_severity": "critical",
            "final_remediation": "Assessor decision.",
        },
    )
    assert verified.status_code == 200

    analyzed = await client.post(
        f"/api/v1/findings/{finding.id}/analyze", headers=headers
    )
    assert analyzed.status_code == 200
    await db.refresh(finding)
    assert finding.final_severity is Severity.CRITICAL
    assert finding.verification_status is VerificationStatus.CONFIRMED
    assert finding.final_remediation == "Assessor decision."
    assert finding.ai_suggested_severity is Severity.MEDIUM


async def test_evidence_note_and_file_validation(
    client: AsyncClient,
    db: AsyncSession,
    monkeypatch,
) -> None:
    _, headers, assessment = await _setup(client, db)
    finding = await create_finding(db, assessment)

    note = await client.post(
        f"/api/v1/findings/{finding.id}/evidence",
        headers=headers,
        data={"note": "Observed manually in a test account."},
    )
    assert note.status_code == 201, note.text
    assert note.json()["type"] == "note"
    assert note.json()["content"] == "Observed manually in a test account."
    assert note.json()["sha256"] is not None

    empty = await client.post(
        f"/api/v1/findings/{finding.id}/evidence",
        headers=headers,
        data={"note": "   "},
    )
    assert empty.status_code == 422

    nothing = await client.post(
        f"/api/v1/findings/{finding.id}/evidence", headers=headers, data={}
    )
    assert nothing.status_code == 422

    both = await client.post(
        f"/api/v1/findings/{finding.id}/evidence",
        headers=headers,
        data={"note": "also a note"},
        files={"file": ("note.txt", b"hello", "text/plain")},
    )
    assert both.status_code == 422

    uploaded = await client.post(
        f"/api/v1/findings/{finding.id}/evidence",
        headers=headers,
        files={"file": ("screenshot.png", b"\x89PNG\r\n\x1a\nhello", "image/png")},
    )
    assert uploaded.status_code == 201, uploaded.text
    body = uploaded.json()
    assert body["type"] == "file"
    assert body["filename"].endswith(".png")
    assert body["content"] is None
    assert body["sha256"] is not None
    path = resolve_data_path(
        get_settings(), f"uploads/{assessment.id}/{finding.id}/{body['filename']}"
    )
    assert path.is_file()

    bad_extension = await client.post(
        f"/api/v1/findings/{finding.id}/evidence",
        headers=headers,
        files={"file": ("payload.exe", b"MZ", "application/octet-stream")},
    )
    assert bad_extension.status_code == 422

    bad_mime = await client.post(
        f"/api/v1/findings/{finding.id}/evidence",
        headers=headers,
        files={"file": ("payload.png", b"\x89PNG\r\n\x1a\nhello", "text/plain")},
    )
    assert bad_mime.status_code == 422

    bad_signature = await client.post(
        f"/api/v1/findings/{finding.id}/evidence",
        headers=headers,
        files={"file": ("payload.pdf", b"not a pdf", "application/pdf")},
    )
    assert bad_signature.status_code == 422

    original_limit = get_settings().max_upload_bytes
    monkeypatch.setattr(get_settings(), "max_upload_bytes", 4)
    too_large = await client.post(
        f"/api/v1/findings/{finding.id}/evidence",
        headers=headers,
        files={"file": ("big.txt", b"12345", "text/plain")},
    )
    monkeypatch.setattr(get_settings(), "max_upload_bytes", original_limit)
    assert too_large.status_code == 413

    listed = await client.get(
        f"/api/v1/findings/{finding.id}/evidence", headers=headers
    )
    assert listed.status_code == 200
    assert len(listed.json()) == 2

    evidence_rows = (
        (await db.execute(select(Evidence).where(Evidence.finding_id == finding.id)))
        .scalars()
        .all()
    )
    assert {row.type.value for row in evidence_rows} == {"note", "file"}


async def test_evidence_for_unknown_finding_returns_404(
    client: AsyncClient, db: AsyncSession
) -> None:
    _, headers, _ = await _setup(client, db)
    response = await client.get("/api/v1/findings/9999/evidence", headers=headers)
    assert response.status_code == 404
