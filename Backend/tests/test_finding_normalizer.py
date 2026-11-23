from __future__ import annotations

import json
from typing import Any

import pytest
from app.db.base import utcnow
from app.db.enums import (
    EvidenceType,
    FindingCategory,
    FindingSource,
    ScanStatus,
    ScanTool,
    Severity,
    VerificationStatus,
)
from app.db.models import Assessment, Evidence, Finding, Scan, User
from app.services.finding_normalizer import (
    ZapParseError,
    categorize_alert,
    fingerprint,
    normalize_nmap_result,
    normalize_url_for_fingerprint,
    normalize_zap_result,
    owasp_category_for,
    parse_zap_document,
    severity_from_risk,
)
from app.services.nmap_parser import parse_nmap_xml
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from tests.fakes import NMAP_FIXTURE, ZAP_MESSAGE_FIXTURE, load_zap_alerts
from tests.utils import create_assessment, create_user


async def _scan(
    db: AsyncSession,
    assessment: Assessment,
    user: User,
    *,
    tool: ScanTool = ScanTool.ZAP,
    profile: str = "baseline",
    target: str = "http://127.0.0.1:3000/",
) -> Scan:
    scan = Scan(
        assessment_id=assessment.id,
        tool=tool,
        profile=profile,
        target=target,
        status=ScanStatus.COMPLETED,
        progress=100,
        started_at=utcnow(),
        finished_at=utcnow(),
        parameters={},
        created_by=user.id,
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)
    return scan


def _zap_document(
    alerts: list[dict[str, Any]] | None = None, *, with_message: bool = True
) -> dict[str, Any]:
    items = [dict(alert) for alert in (alerts or load_zap_alerts())]
    if with_message and items:
        message = json.loads(ZAP_MESSAGE_FIXTURE.read_text(encoding="utf-8"))
        items[0]["httpMessage"] = {
            key: message.get(key)
            for key in (
                "requestHeader",
                "requestBody",
                "responseHeader",
                "responseBody",
            )
            if message.get(key) is not None
        }
    return {"tool": "zap", "version": "2.17.0", "alerts": items}


def test_url_normalization_ignores_query_and_default_port() -> None:
    assert (
        normalize_url_for_fingerprint("HTTP://Example.COM:80/a/b/?q=1#frag")
        == "http://example.com/a/b"
    )
    assert (
        normalize_url_for_fingerprint("https://example.com:443/")
        == "https://example.com/"
    )
    assert (
        normalize_url_for_fingerprint("https://example.com:8443/api/v1")
        == "https://example.com:8443/api/v1"
    )
    assert normalize_url_for_fingerprint("") == ""
    assert normalize_url_for_fingerprint(None) == ""


def test_fingerprint_is_stable_across_query_values() -> None:
    first = fingerprint(
        "zap", "40018", "GET", "http://127.0.0.1:3000/search?q=one", "q"
    )
    second = fingerprint(
        "zap", "40018", "GET", "http://127.0.0.1:3000/search?q=two#x", "q"
    )
    assert first == second
    assert first != fingerprint(
        "zap", "40018", "POST", "http://127.0.0.1:3000/search?q=one", "q"
    )
    assert first != fingerprint(
        "zap", "40018", "GET", "http://127.0.0.1:3000/search?q=one", "id"
    )
    assert first != fingerprint(
        "zap", "10020", "GET", "http://127.0.0.1:3000/search?q=one", "q"
    )


@pytest.mark.parametrize(
    ("risk", "expected"),
    [
        ("High", Severity.HIGH),
        ("MEDIUM", Severity.MEDIUM),
        ("low", Severity.LOW),
        ("Informational", Severity.INFO),
        ("", Severity.INFO),
        (None, Severity.INFO),
    ],
)
def test_severity_from_risk(risk: Any, expected: Severity) -> None:
    assert severity_from_risk(risk) == expected


def test_category_and_owasp_mapping() -> None:
    alerts = {alert["pluginId"]: alert for alert in load_zap_alerts()}

    sqli = alerts["40018"]
    assert categorize_alert(sqli) is FindingCategory.INJECTION
    assert owasp_category_for(FindingCategory.INJECTION, sqli).startswith("A03:2021")

    clickjacking = alerts["10020"]
    assert categorize_alert(clickjacking) is FindingCategory.SECURITY_CONFIGURATION
    assert owasp_category_for(
        FindingCategory.SECURITY_CONFIGURATION, clickjacking
    ).startswith("A05:2021")

    cookie = alerts["10010"]
    assert categorize_alert(cookie) is FindingCategory.SESSION_MANAGEMENT
    assert owasp_category_for(
        FindingCategory.SESSION_MANAGEMENT, cookie
    ).startswith("A07:2021")

    comments = alerts["10027"]
    assert categorize_alert(comments) is FindingCategory.INFORMATION_DISCLOSURE
    assert owasp_category_for(
        FindingCategory.INFORMATION_DISCLOSURE, comments
    ).startswith("A01:2021")

    assert categorize_alert({"alert": "SQL Injection"}) is FindingCategory.INJECTION
    assert (
        categorize_alert({"cweid": "79", "alert": "Unclassified"})
        is FindingCategory.INJECTION
    )
    assert (
        categorize_alert({"pluginId": "10020", "alert": "Unclassified"})
        is FindingCategory.SECURITY_CONFIGURATION
    )
    assert (
        categorize_alert({"alert": "Something new"}) is FindingCategory.UNCATEGORIZED
    )


async def test_nmap_normalization_creates_notable_findings_and_upserts(
    db: AsyncSession,
) -> None:
    user = await create_user(db, email="nmap-findings@example.test")
    assessment = await create_assessment(db, user=user, authorized=True)
    parsed = parse_nmap_xml(NMAP_FIXTURE.read_bytes())
    first_scan = await _scan(
        db,
        assessment,
        user,
        tool=ScanTool.NMAP,
        profile="quick",
        target="127.0.0.1",
    )

    counts = await normalize_nmap_result(db, first_scan, parsed)
    await db.commit()
    assert counts == {"created": 6, "updated": 0, "total": 6}

    findings = (
        (await db.execute(select(Finding).where(Finding.assessment_id == assessment.id)))
        .scalars()
        .all()
    )
    assert len(findings) == 6
    assert all(finding.source is FindingSource.NMAP for finding in findings)
    assert all(finding.scan_id == first_scan.id for finding in findings)

    titles = {finding.title for finding in findings}
    assert "SSH service exposed on 22/tcp" in titles
    assert "Redis service exposed on 6379/tcp" in titles
    assert "Service version disclosed on 6379/tcp" in titles
    assert not any("5432" in title for title in titles)

    ssh = next(finding for finding in findings if "22/tcp" in finding.title)
    assert ssh.category is FindingCategory.SECURITY_CONFIGURATION
    assert ssh.tool_severity is Severity.INFO
    assert ssh.affected_url == "127.0.0.1:22"
    assert "OpenSSH" in (ssh.description or "")

    version = next(finding for finding in findings if "version disclosed" in finding.title)
    assert version.category is FindingCategory.INFORMATION_DISCLOSURE
    assert version.cwe == "CWE-200"

    second_scan = await _scan(
        db,
        assessment,
        user,
        tool=ScanTool.NMAP,
        profile="quick",
        target="127.0.0.1",
    )
    again = await normalize_nmap_result(db, second_scan, parsed)
    await db.commit()
    assert again == {"created": 0, "updated": 6, "total": 6}
    total = await db.scalar(
        select(func.count(Finding.id)).where(Finding.assessment_id == assessment.id)
    )
    assert total == 6


async def test_zap_normalization_dedupes_and_preserves_review_state(
    db: AsyncSession,
) -> None:
    user = await create_user(db, email="zap-findings@example.test")
    assessment = await create_assessment(db, user=user, authorized=True)
    document = _zap_document()
    first_scan = await _scan(db, assessment, user)

    counts = await normalize_zap_result(db, first_scan, document)
    await db.commit()
    assert counts == {"created": 4, "updated": 0, "total": 4}

    findings = (
        (await db.execute(select(Finding).where(Finding.assessment_id == assessment.id)))
        .scalars()
        .all()
    )
    assert len(findings) == 4
    assert all(finding.source is FindingSource.ZAP for finding in findings)

    sqli = next(finding for finding in findings if finding.title == "SQL Injection")
    assert sqli.tool_severity is Severity.HIGH
    assert sqli.category is FindingCategory.INJECTION
    assert sqli.cwe == "CWE-89"
    assert sqli.http_method == "GET"
    assert sqli.parameter == "q"
    assert sqli.affected_url is not None
    assert sqli.affected_url.endswith("?q=test")
    assert sqli.owasp_category is not None
    assert sqli.owasp_category.startswith("A03:2021")
    assert sqli.verification_status is VerificationStatus.PENDING
    assert sqli.first_seen_at == sqli.last_seen_at

    clickjacking = next(
        finding
        for finding in findings
        if finding.title == "Missing Anti-clickjacking Header"
    )
    assert clickjacking.tool_severity is Severity.MEDIUM
    assert clickjacking.category is FindingCategory.SECURITY_CONFIGURATION

    cookie = next(
        finding for finding in findings if finding.title == "Cookie No HttpOnly Flag"
    )
    assert cookie.tool_severity is Severity.LOW
    assert cookie.category is FindingCategory.SESSION_MANAGEMENT
    assert cookie.parameter == "sessionid"

    comments = next(
        finding
        for finding in findings
        if finding.title == "Information Disclosure - Suspicious Comments"
    )
    assert comments.tool_severity is Severity.INFO
    assert comments.category is FindingCategory.INFORMATION_DISCLOSURE

    sqli.verification_status = VerificationStatus.CONFIRMED
    sqli.final_severity = Severity.CRITICAL
    sqli.ai_suggested_severity = Severity.HIGH
    sqli.final_remediation = "Use parameterised queries."
    sqli.rejection_reason = "not rejected"
    sqli.verified_by = user.id
    sqli.verified_at = utcnow()
    sqli.seen_count = 1
    first_seen = sqli.first_seen_at
    await db.commit()

    second_scan = await _scan(db, assessment, user)
    again = await normalize_zap_result(db, second_scan, document)
    await db.commit()
    assert again == {"created": 0, "updated": 4, "total": 4}
    total = await db.scalar(
        select(func.count(Finding.id)).where(Finding.assessment_id == assessment.id)
    )
    assert total == 4

    await db.refresh(sqli)
    assert sqli.verification_status is VerificationStatus.CONFIRMED
    assert sqli.final_severity is Severity.CRITICAL
    assert sqli.ai_suggested_severity is Severity.HIGH
    assert sqli.final_remediation == "Use parameterised queries."
    assert sqli.rejection_reason == "not rejected"
    assert sqli.verified_by == user.id
    assert sqli.verified_at is not None
    assert sqli.first_seen_at == first_seen
    assert sqli.seen_count == 2
    assert sqli.scan_id == second_scan.id
    assert sqli.last_seen_at >= first_seen


async def test_zap_http_evidence_is_deduped_across_rescans(db: AsyncSession) -> None:
    user = await create_user(db, email="zap-evidence@example.test")
    assessment = await create_assessment(db, user=user, authorized=True)
    document = _zap_document()
    first_scan = await _scan(db, assessment, user)
    await normalize_zap_result(db, first_scan, document)
    await db.commit()

    sqli = await db.scalar(
        select(Finding).where(
            Finding.assessment_id == assessment.id,
            Finding.title == "SQL Injection",
        )
    )
    assert sqli is not None
    evidence = (
        (
            await db.execute(
                select(Evidence).where(Evidence.finding_id == sqli.id)
            )
        )
        .scalars()
        .all()
    )
    assert len(evidence) == 1
    assert evidence[0].type is EvidenceType.HTTP_EXCHANGE
    assert evidence[0].scan_id == first_scan.id
    assert "REQUEST" in (evidence[0].content or "")
    assert "HTTP/1.1 500" in (evidence[0].content or "")
    assert evidence[0].sha256 is not None

    second_scan = await _scan(db, assessment, user)
    await normalize_zap_result(db, second_scan, document)
    await db.commit()
    count = await db.scalar(
        select(func.count(Evidence.id)).where(Evidence.finding_id == sqli.id)
    )
    assert count == 1

    changed = _zap_document()
    changed["alerts"][0]["httpMessage"]["responseBody"] = "different response"
    third_scan = await _scan(db, assessment, user)
    await normalize_zap_result(db, third_scan, changed)
    await db.commit()
    count = await db.scalar(
        select(func.count(Evidence.id)).where(Evidence.finding_id == sqli.id)
    )
    assert count == 2


def test_parse_zap_document_rejects_bad_input() -> None:
    with pytest.raises(ZapParseError, match="empty"):
        parse_zap_document(b"")
    with pytest.raises(ZapParseError, match="invalid ZAP JSON"):
        parse_zap_document(b"{not json")
    with pytest.raises(ZapParseError, match="not an object"):
        parse_zap_document(json.dumps(["alerts"]).encode("utf-8"))
    with pytest.raises(ZapParseError, match="not a list"):
        parse_zap_document(json.dumps({"alerts": 5}).encode("utf-8"))
    assert parse_zap_document(json.dumps({"alerts": []}).encode("utf-8")) == {
        "alerts": []
    }


async def test_normalize_zap_result_requires_alerts_list(db: AsyncSession) -> None:
    user = await create_user(db, email="zap-bad-doc@example.test")
    assessment = await create_assessment(db, user=user, authorized=True)
    scan = await _scan(db, assessment, user)
    with pytest.raises(ZapParseError, match="alerts is not a list"):
        await normalize_zap_result(db, scan, {"alerts": "nope"})
