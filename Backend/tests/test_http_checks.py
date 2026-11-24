from __future__ import annotations

import asyncio

import httpx
from app.core.config import get_settings
from app.db.enums import (
    ScanStatus,
    ScanTool,
    ScopeKind,
)
from app.db.models import AuditLog, Evidence, Finding, Scan, ScopeItem
from app.schemas.http_checks import (
    AccessRule,
    HttpCheckConfigIn,
    HttpCheckLimits,
    LoginSpec,
    TestAccountCreate,
)
from app.services import http_checks as service
from app.services.credentials import decrypt_secret
from app.services.finding_normalizer import normalize_http_checks_result
from app.services.sanitizer import redact_known_secrets
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from tests.utils import add_scope, create_assessment, create_user, login_headers


def _root_headers(origin: str | None = None) -> dict[str, str]:
    headers = {
        "server": "FakeServer/1.0",
        "content-type": "text/html",
        "set-cookie": "session=session-secret; Path=/",
    }
    if origin:
        headers["access-control-allow-origin"] = origin
    return headers


def _handler(calls: list[httpx.Request]):
    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        path = request.url.path
        if path == "/login":
            body = request.content.decode("utf-8", errors="replace")
            if "admin" in body or "staff" in body:
                if "secret-pass" in body or "password=" in body:
                    return httpx.Response(
                        200,
                        text="welcome",
                        headers={"set-cookie": "session=session-secret; Path=/"},
                    )
                return httpx.Response(200, text="wrong password")
            return httpx.Response(200, text="invalid username")
        if path == "/admin":
            return httpx.Response(200, text="admin area")
        if path.startswith("/penpal-nonexistent"):
            return httpx.Response(404, text="Traceback (most recent call last): boom")
        return httpx.Response(
            200,
            text="hello",
            headers=_root_headers(request.headers.get("origin")),
        )

    return handler


async def _scan(db: AsyncSession, assessment) -> Scan:
    scan = Scan(
        assessment_id=assessment.id,
        tool=ScanTool.HTTP_CHECKS,
        profile="config_baseline",
        target="http://127.0.0.1:3000/",
        status=ScanStatus.RUNNING,
        progress=10,
        parameters={},
        created_by=assessment.created_by,
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)
    return scan


async def _rules(db: AsyncSession, assessment_id: int) -> list[ScopeItem]:
    return list(
        (
            await db.execute(
                select(ScopeItem).where(ScopeItem.assessment_id == assessment_id)
            )
        )
        .scalars()
        .all()
    )


async def _configure(
    db: AsyncSession,
    assessment,
    user,
    *,
    access_rules: list[AccessRule] | None = None,
    limits: HttpCheckLimits | None = None,
):
    payload = HttpCheckConfigIn(
        login=LoginSpec(url="/login", content_type="form"),
        access_rules=access_rules or [],
        roles=["staff", "admin"],
        limits=limits or HttpCheckLimits(min_login_interval_seconds=0, max_rps=10),
    )
    return await service.upsert_config(db, assessment, payload, user)


async def _accounts(db: AsyncSession, assessment, user, settings):
    for role in ("staff", "admin"):
        await service.create_account(
            db,
            assessment,
            TestAccountCreate(
                role=role,
                username=f"{role}-user",
                password="secret-pass",
            ),
            user,
            settings,
        )


async def test_http_check_config_and_write_only_accounts(
    client: AsyncClient, db: AsyncSession
) -> None:
    user = await create_user(db, email="http-config@example.test")
    headers = await login_headers(client, "http-config@example.test")
    assessment = await create_assessment(db, user=user, authorized=True)
    base = f"/api/v1/assessments/{assessment.id}"

    missing = await client.get(f"{base}/http-check-config", headers=headers)
    assert missing.status_code == 404

    config_response = await client.put(
        f"{base}/http-check-config",
        headers=headers,
        json={
            "login": {
                "url": "/login",
                "content_type": "json",
                "username_field": "email",
                "password_field": "password",
            },
            "access_rules": [
                {
                    "path": "/admin",
                    "method": "GET",
                    "allowed_roles": ["admin"],
                }
            ],
            "roles": ["staff", "admin"],
            "limits": {"max_requests": 50, "max_rps": 2, "max_login_attempts": 3},
        },
    )
    assert config_response.status_code == 200, config_response.text
    assert config_response.json()["roles"] == ["staff", "admin"]
    assert config_response.json()["access_rules"][0]["path"] == "/admin"

    created = await client.post(
        f"{base}/test-accounts",
        headers=headers,
        json={"role": "staff", "username": "staff01", "password": "Secret-Pass-1"},
    )
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["role"] == "staff"
    assert body["username"] == "staff01"
    assert "password" not in body

    account = await db.scalar(
        select(service.TestAccount).where(service.TestAccount.id == body["id"])
    )
    assert account is not None
    assert account.password_encrypted != "Secret-Pass-1"
    assert decrypt_secret(account.password_encrypted, get_settings()) == "Secret-Pass-1"

    listed = await client.get(f"{base}/test-accounts", headers=headers)
    assert listed.status_code == 200
    assert listed.json()[0]["username"] == "staff01"
    assert "password" not in listed.json()[0]

    duplicate = await client.post(
        f"{base}/test-accounts",
        headers=headers,
        json={"role": "staff", "username": "staff01", "password": "x"},
    )
    assert duplicate.status_code == 409

    bad_role = await client.post(
        f"{base}/test-accounts",
        headers=headers,
        json={"role": "customer", "username": "customer", "password": "x"},
    )
    assert bad_role.status_code == 422

    deleted = await client.delete(
        f"{base}/test-accounts/{body['id']}", headers=headers
    )
    assert deleted.status_code == 204
    assert (
        await client.get(f"{base}/test-accounts", headers=headers)
    ).json() == []


async def test_config_baseline_findings_and_evidence(
    db: AsyncSession, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    user = await create_user(db, email="http-baseline@example.test")
    assessment = await create_assessment(db, user=user, authorized=True)
    await add_scope(db, assessment, ScopeKind.HOST, "127.0.0.1")
    scan = await _scan(db, assessment)
    calls: list[httpx.Request] = []
    runner = service.HttpCheckRunner(
        get_settings(), session_factory, transport=httpx.MockTransport(_handler(calls))
    )

    async def progress(_value: int) -> None:
        return None

    result = await runner.run(
        scan=scan,
        assessment=assessment,
        rules=await _rules(db, assessment.id),
        user_id=user.id,
        confirm_lockout_test=False,
        cancel_event=asyncio.Event(),
        progress=progress,
    )
    assert result.document["profile"] == "config_baseline"
    rule_ids = {item["rule_id"] for item in result.findings}
    assert "http-config:missing-csp" in rule_ids
    assert "http-config:missing-frame-protection" in rule_ids
    assert "http-config:https-not-enabled" in rule_ids
    assert "http-config:server-banner" in rule_ids
    assert "http-config:cors-reflected-origin" in rule_ids
    assert "http-config:debug-error-page" in rule_ids
    assert "http-session:httponly:session" in rule_ids

    normalized = await normalize_http_checks_result(
        db, scan, result.findings
    )
    await db.commit()
    assert normalized["created"] >= 5
    findings = (
        (await db.execute(select(Finding).where(Finding.scan_id == scan.id)))
        .scalars()
        .all()
    )
    assert {str(finding.source) for finding in findings} == {"http_checks"}
    evidence_rows = (
        (await db.execute(select(Evidence).where(Evidence.scan_id == scan.id)))
        .scalars()
        .all()
    )
    assert evidence_rows
    assert any("CURL EQUIVALENT" in (row.content or "") for row in evidence_rows)
    assert all("secret-pass" not in (row.content or "") for row in evidence_rows)


async def test_session_and_access_control_findings(
    db: AsyncSession, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    user = await create_user(db, email="http-session@example.test")
    assessment = await create_assessment(db, user=user, authorized=True)
    await add_scope(db, assessment, ScopeKind.HOST, "127.0.0.1")
    settings = get_settings()
    await _configure(
        db,
        assessment,
        user,
        access_rules=[
            AccessRule(path="/admin", method="GET", allowed_roles=["admin"])
        ],
    )
    await _accounts(db, assessment, user, settings)
    calls: list[httpx.Request] = []
    runner = service.HttpCheckRunner(
        settings, session_factory, transport=httpx.MockTransport(_handler(calls))
    )
    scan = await _scan(db, assessment)
    scan.profile = "access_control"
    await db.commit()

    async def progress(_value: int) -> None:
        return None

    result = await runner.run(
        scan=scan,
        assessment=assessment,
        rules=await _rules(db, assessment.id),
        user_id=user.id,
        confirm_lockout_test=False,
        cancel_event=asyncio.Event(),
        progress=progress,
    )
    rule_ids = {item["rule_id"] for item in result.findings}
    assert "http-access:unauth:GET:/admin" in rule_ids
    assert "http-access:role:GET:/admin:staff" in rule_ids
    assert "http-session:httponly:session" in rule_ids
    all_evidence = "\n".join(item["evidence"] for item in result.findings)
    assert "secret-pass" not in all_evidence
    assert "session-secret" not in all_evidence


async def test_auth_limited_user_enumeration_and_weak_password(
    db: AsyncSession, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    user = await create_user(db, email="http-auth@example.test")
    assessment = await create_assessment(db, user=user, authorized=True)
    await add_scope(db, assessment, ScopeKind.HOST, "127.0.0.1")
    settings = get_settings()
    await _configure(
        db,
        assessment,
        user,
        limits=HttpCheckLimits(
            max_login_attempts=8,
            min_login_interval_seconds=0,
            max_rps=10,
        ),
    )
    await _accounts(db, assessment, user, settings)
    scan = await _scan(db, assessment)
    scan.profile = "auth_limited"
    await db.commit()
    calls: list[httpx.Request] = []
    runner = service.HttpCheckRunner(
        settings, session_factory, transport=httpx.MockTransport(_handler(calls))
    )

    async def progress(_value: int) -> None:
        return None

    result = await runner.run(
        scan=scan,
        assessment=assessment,
        rules=await _rules(db, assessment.id),
        user_id=user.id,
        confirm_lockout_test=False,
        cancel_event=asyncio.Event(),
        progress=progress,
    )
    rule_ids = {item["rule_id"] for item in result.findings}
    assert "http-auth:user-enumeration" in rule_ids
    assert "http-auth:weak-password:admin" in rule_ids
    assert any("lockout test skipped" in note for note in result.document["notes"])


async def test_redirect_out_of_scope_is_blocked(
    db: AsyncSession, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    user = await create_user(db, email="http-redirect@example.test")
    assessment = await create_assessment(db, user=user, authorized=True)
    await add_scope(db, assessment, ScopeKind.HOST, "127.0.0.1")
    scan = await _scan(db, assessment)
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(302, headers={"location": "http://evil.test/"})

    runner = service.HttpCheckRunner(
        get_settings(), session_factory, transport=httpx.MockTransport(handler)
    )

    async def progress(_value: int) -> None:
        return None

    await runner.run(
        scan=scan,
        assessment=assessment,
        rules=await _rules(db, assessment.id),
        user_id=user.id,
        confirm_lockout_test=False,
        cancel_event=asyncio.Event(),
        progress=progress,
    )
    assert len(calls) == 1
    denied = (
        await db.execute(
            select(AuditLog).where(
                AuditLog.action == "http_check.request",
                AuditLog.details["allowed"].as_boolean() == False,  # noqa: E712
            )
        )
    ).scalars()
    assert list(denied)


async def test_request_budget_stops_profile(
    db: AsyncSession, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    user = await create_user(db, email="http-budget@example.test")
    assessment = await create_assessment(db, user=user, authorized=True)
    await add_scope(db, assessment, ScopeKind.HOST, "127.0.0.1")
    await _configure(
        db,
        assessment,
        user,
        limits=HttpCheckLimits(max_requests=1, max_rps=10, min_login_interval_seconds=0),
    )
    scan = await _scan(db, assessment)
    calls: list[httpx.Request] = []
    runner = service.HttpCheckRunner(
        get_settings(), session_factory, transport=httpx.MockTransport(_handler(calls))
    )

    async def progress(_value: int) -> None:
        return None

    result = await runner.run(
        scan=scan,
        assessment=assessment,
        rules=await _rules(db, assessment.id),
        user_id=user.id,
        confirm_lockout_test=False,
        cancel_event=asyncio.Event(),
        progress=progress,
    )
    assert len(calls) == 1
    assert any("request budget" in note for note in result.document["notes"])


def test_known_secret_redaction_is_exact() -> None:
    assert (
        redact_known_secrets("password=secret-pass; cookie=abc", ["secret-pass"])
        == "password=[REDACTED_KNOWN_SECRET]; cookie=abc"
    )
