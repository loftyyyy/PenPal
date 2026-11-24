"""Seed and bootstrap script.

Usage:
    python scripts/seed.py --admin-only
    python scripts/seed.py --demo
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import sys
from pathlib import Path

from sqlalchemy import select

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core.config import get_settings
from app.db.base import utcnow
from app.db.enums import (
    AIAnalysisStatus,
    AIFunction,
    AssessmentStatus,
    EvidenceType,
    FindingCategory,
    FindingSource,
    Role,
    ScanStatus,
    ScanTool,
    ScopeKind,
    Severity,
    VerificationStatus,
)
from app.db.models import (
    AIAnalysis,
    Assessment,
    Evidence,
    Finding,
    Scan,
    ScopeItem,
    User,
)
from app.db.session import dispose_engine, get_session_factory
from app.services.auth import bootstrap_admin

DEMO_NAME = "LSRS demo assessment"
DEMO_TARGET = "http://target:3000"


def _fingerprint(title: str, parameter: str = "") -> str:
    return hashlib.sha256(
        f"seed|{title}|{parameter}".encode()
    ).hexdigest()


async def _ensure_admin(db, settings) -> User:
    created = await bootstrap_admin(db, settings)
    if created is not None:
        print(f"Created administrator {created.email}")
        return created
    admin = await db.scalar(
        select(User).where(User.email == settings.first_admin_email.strip().lower())
    )
    if admin is None:
        admin = await db.scalar(select(User).where(User.role == Role.ADMIN))
    if admin is None:
        raise RuntimeError(
            "No administrator exists and bootstrap did not create one; "
            "check FIRST_ADMIN_EMAIL/FIRST_ADMIN_PASSWORD"
        )
    print(f"Administrator already present: {admin.email}")
    return admin


def _finding(
    assessment_id: int,
    *,
    title: str,
    description: str,
    category: FindingCategory,
    source: FindingSource,
    tool_severity: Severity,
    affected_url: str,
    parameter: str,
    raw: dict,
) -> Finding:
    now = utcnow()
    return Finding(
        assessment_id=assessment_id,
        source=source,
        fingerprint=_fingerprint(title, parameter),
        title=title,
        description=description,
        category=category,
        affected_url=affected_url,
        http_method="GET",
        parameter=parameter or None,
        tool_severity=tool_severity,
        tool_confidence="High" if source is FindingSource.ZAP else "syn-ack",
        raw=raw,
        first_seen_at=now,
        last_seen_at=now,
        seen_count=1,
    )


async def _seed_demo(db, admin: User) -> None:
    existing = await db.scalar(
        select(Assessment).where(
            Assessment.name == DEMO_NAME,
            Assessment.created_by == admin.id,
        )
    )
    if existing is not None:
        print(f"Demo assessment already present (id={existing.id}); nothing to do")
        return

    now = utcnow()
    assessment = Assessment(
        name=DEMO_NAME,
        description=(
            "Demo assessment against the Compose stand-in target. Synthetic data for "
            "the course demo; never use this against an unauthorized system."
        ),
        target_name="Love & Styles Rental System (demo stand-in)",
        target_base_url=DEMO_TARGET,
        target_description="OWASP Juice Shop used as a local stand-in for LSRS.",
        owner_name="LSRS owners (demo authorization)",
        authorization_reference="demo-authorization-letter.pdf",
        authorization_confirmed=True,
        authorization_confirmed_by=admin.id,
        authorization_confirmed_at=now,
        hosting_environment="Docker Compose internal network",
        selected_categories=[
            "authentication",
            "access_control",
            "injection",
            "session_management",
            "security_configuration",
        ],
        status=AssessmentStatus.IN_PROGRESS,
        created_by=admin.id,
    )
    db.add(assessment)
    await db.flush()

    db.add_all(
        [
            ScopeItem(
                assessment_id=assessment.id,
                kind=ScopeKind.HOST,
                value="target",
                in_scope=True,
                note="Compose dev target",
            ),
            ScopeItem(
                assessment_id=assessment.id,
                kind=ScopeKind.URL_PREFIX,
                value=DEMO_TARGET,
                in_scope=True,
                note="Base URL",
            ),
            ScopeItem(
                assessment_id=assessment.id,
                kind=ScopeKind.URL_PREFIX,
                value=f"{DEMO_TARGET}/admin",
                in_scope=False,
                note="Out of scope for this demo",
            ),
        ]
    )

    nmap_scan = Scan(
        assessment_id=assessment.id,
        tool=ScanTool.NMAP,
        profile="quick",
        target="target",
        status=ScanStatus.COMPLETED,
        progress=100,
        started_at=now,
        finished_at=now,
        tool_version="7.95",
        parameters={"ports": [3000], "result_summary": {"hosts": 1, "open_ports": 1}},
        created_by=admin.id,
    )
    zap_scan = Scan(
        assessment_id=assessment.id,
        tool=ScanTool.ZAP,
        profile="baseline",
        target=f"{DEMO_TARGET}/",
        status=ScanStatus.COMPLETED,
        progress=100,
        started_at=now,
        finished_at=now,
        tool_version="2.17.0",
        parameters={
            "result_summary": {"alerts": 4, "high": 1, "medium": 1, "low": 1, "info": 1}
        },
        created_by=admin.id,
    )
    db.add_all([nmap_scan, zap_scan])
    await db.flush()

    injection = _finding(
        assessment.id,
        title="SQL injection in product search",
        description=(
            "The search parameter reaches a SQL statement. The demo response contained "
            "a database syntax error and should be verified manually."
        ),
        category=FindingCategory.INJECTION,
        source=FindingSource.ZAP,
        tool_severity=Severity.HIGH,
        affected_url=f"{DEMO_TARGET}/rest/products/search?q=test",
        parameter="q",
        raw={
            "pluginId": "40018",
            "alert": "SQL Injection",
            "risk": "High",
            "cweid": "89",
            "param": "q",
        },
    )
    clickjacking = _finding(
        assessment.id,
        title="Missing anti-clickjacking header",
        description="The response did not include a frame-busting header.",
        category=FindingCategory.SECURITY_CONFIGURATION,
        source=FindingSource.ZAP,
        tool_severity=Severity.MEDIUM,
        affected_url=f"{DEMO_TARGET}/",
        parameter="",
        raw={"pluginId": "10020", "alert": "Missing Anti-clickjacking Header"},
    )
    cookie = _finding(
        assessment.id,
        title="Session cookie without HttpOnly",
        description="A session cookie was set without the HttpOnly flag.",
        category=FindingCategory.SESSION_MANAGEMENT,
        source=FindingSource.ZAP,
        tool_severity=Severity.LOW,
        affected_url=f"{DEMO_TARGET}/",
        parameter="sessionid",
        raw={"pluginId": "10010", "alert": "Cookie No HttpOnly Flag"},
    )
    disclosure = _finding(
        assessment.id,
        title="Service version disclosed on 3000/tcp",
        description="Nmap identified the Node.js Express framework version.",
        category=FindingCategory.INFORMATION_DISCLOSURE,
        source=FindingSource.NMAP,
        tool_severity=Severity.INFO,
        affected_url="target:3000",
        parameter="",
        raw={"port": 3000, "service": {"product": "Node.js Express framework"}},
    )
    pending = _finding(
        assessment.id,
        title="Access-control check needs manual verification",
        description=(
            "Review whether a staff test account can reach an administrator endpoint. "
            "This finding is intentionally left pending."
        ),
        category=FindingCategory.ACCESS_CONTROL,
        source=FindingSource.MANUAL,
        tool_severity=Severity.MEDIUM,
        affected_url=f"{DEMO_TARGET}/rest/user/1",
        parameter="id",
        raw={"manual": True},
    )
    false_positive = _finding(
        assessment.id,
        title="Directory browsing on the static demo page",
        description="The reported listing was a static demo page, not a directory index.",
        category=FindingCategory.EXPOSED_FILES,
        source=FindingSource.ZAP,
        tool_severity=Severity.LOW,
        affected_url=f"{DEMO_TARGET}/",
        parameter="",
        raw={"pluginId": "0", "alert": "Directory Browsing"},
    )
    needs_retest = _finding(
        assessment.id,
        title="Rate limit on login endpoint needs retest",
        description="Retest after the target configuration change.",
        category=FindingCategory.AUTHENTICATION,
        source=FindingSource.MANUAL,
        tool_severity=Severity.MEDIUM,
        affected_url=f"{DEMO_TARGET}/rest/user/login",
        parameter="email",
        raw={"manual": True},
    )
    db.add_all(
        [injection, clickjacking, cookie, disclosure, pending, false_positive, needs_retest]
    )
    await db.flush()

    injection.verification_status = VerificationStatus.CONFIRMED
    injection.final_severity = Severity.CRITICAL
    injection.likelihood = 5
    injection.impact = 5
    injection.final_remediation = "Use parameterised queries and validate search input."
    injection.verified_by = admin.id
    injection.verified_at = now
    clickjacking.verification_status = VerificationStatus.CONFIRMED
    clickjacking.final_severity = Severity.MEDIUM
    clickjacking.likelihood = 2
    clickjacking.impact = 3
    clickjacking.final_remediation = "Send X-Frame-Options or frame-ancestors."
    clickjacking.verified_by = admin.id
    clickjacking.verified_at = now
    cookie.verification_status = VerificationStatus.CONFIRMED
    cookie.final_severity = Severity.LOW
    cookie.likelihood = 2
    cookie.impact = 2
    cookie.final_remediation = "Set HttpOnly and Secure on session cookies."
    cookie.verified_by = admin.id
    cookie.verified_at = now
    disclosure.verification_status = VerificationStatus.CONFIRMED
    disclosure.final_severity = Severity.INFO
    disclosure.likelihood = 1
    disclosure.impact = 2
    disclosure.final_remediation = "Hide framework version headers where practical."
    disclosure.verified_by = admin.id
    disclosure.verified_at = now
    false_positive.verification_status = VerificationStatus.FALSE_POSITIVE
    false_positive.rejection_reason = "The path is a static demo page, not a directory index."
    false_positive.verified_by = admin.id
    false_positive.verified_at = now
    needs_retest.verification_status = VerificationStatus.NEEDS_RETEST
    needs_retest.rejection_reason = "Retest after the target configuration change."
    needs_retest.verified_by = admin.id
    needs_retest.verified_at = now

    db.add_all(
        [
            Evidence(
                finding_id=injection.id,
                type=EvidenceType.HTTP_EXCHANGE,
                content=(
                    "REQUEST\nGET /rest/products/search?q=test HTTP/1.1\n"
                    "Host: target:3000\n\nRESPONSE\nHTTP/1.1 500 Internal Server Error\n\n"
                    '{"error":"SQLITE_ERROR: near test: syntax error"}'
                ),
                sha256=hashlib.sha256(b"seed-sqli-evidence").hexdigest(),
                created_by=admin.id,
            ),
            Evidence(
                finding_id=clickjacking.id,
                type=EvidenceType.NOTE,
                content="Checked the response headers in the browser and with curl.",
                sha256=hashlib.sha256(b"seed-clickjacking-note").hexdigest(),
                created_by=admin.id,
            ),
            AIAnalysis(
                finding_id=injection.id,
                function=AIFunction.INTERPRET,
                provider="mock",
                model="mock-deterministic",
                prompt_version="demo",
                input_hash=hashlib.sha256(b"seed-ai-input").hexdigest(),
                sanitized_input=(
                    "FUNCTION: interpret\n<finding_data>"
                    '{"finding":{"title":"SQL injection in product search"}}'
                    "</finding_data>"
                ),
                output={
                    "plain_language_explanation": (
                        "The search field appears to reach a SQL query."
                    ),
                    "why_it_matters": "A confirmed injection could expose database records.",
                    "suggested_severity": "high",
                    "severity_rationale": "Provisional until the assessor verifies it.",
                    "likely_false_positive": False,
                    "confidence": "medium",
                    "owasp_category": "A03:2021 - Injection",
                    "verification_hints": ["Repeat the request and inspect the SQL error."],
                },
                status=AIAnalysisStatus.SUCCESS,
                redaction_report={"password": 1, "cookie_header": 1},
            ),
        ]
    )
    await db.commit()
    print(
        "Demo assessment created: "
        f"id={assessment.id}, confirmed=4, pending=1, false_positive=1, needs_retest=1"
    )


async def run(admin_only: bool) -> None:
    settings = get_settings()
    settings.validate_for_startup()
    factory = get_session_factory()
    async with factory() as db:
        admin = await _ensure_admin(db, settings)
        if not admin_only:
            await _seed_demo(db, admin)
    await dispose_engine()


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed PenPal data")
    parser.add_argument("--admin-only", action="store_true", help="bootstrap first admin only")
    parser.add_argument("--demo", action="store_true", help="bootstrap admin and demo assessment")
    args = parser.parse_args()
    asyncio.run(run(admin_only=args.admin_only and not args.demo))


if __name__ == "__main__":
    main()
