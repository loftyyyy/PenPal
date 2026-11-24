from __future__ import annotations

import asyncio
import json

from app.core.config import Settings
from app.db.enums import (
    AIAnalysisStatus,
    AIFunction,
    Severity,
    VerificationStatus,
)
from app.db.models import AIAnalysis, AuditLog, Evidence, Finding
from app.services.ai.base import ProviderError
from app.services.ai.failover import FailoverProvider
from app.services.ai.mock import MockProvider
from app.services.ai.service import AIAnalysisService, RateLimiter
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from tests.fakes import ScriptedProvider
from tests.utils import add_evidence, create_assessment, create_finding, create_user

VALID_INTERPRET = json.dumps(
    {
        "plain_language_explanation": "The search parameter reaches a SQL query.",
        "why_it_matters": "An attacker could read or alter database records.",
        "suggested_severity": "high",
        "severity_rationale": "Database compromise is possible but needs verification.",
        "likely_false_positive": False,
        "confidence": "medium",
        "owasp_category": "A03:2021 - Injection",
        "verification_hints": [
            "Repeat the request manually and confirm the SQL error.",
            "Test a harmless payload against a test account.",
        ],
    }
)

VALID_REMEDIATE = json.dumps(
    {
        "summary": "Use parameterised queries for the search endpoint.",
        "steps": [
            "Replace string concatenation with bound parameters.",
            "Validate and limit search input length.",
            "Re-test the endpoint after deployment.",
        ],
        "code_or_config_example": "cursor.execute('SELECT * FROM products WHERE name = ?', (q,))",
        "references": ["OWASP SQL Injection Prevention Cheat Sheet (unverified)"],
        "effort": "low",
    }
)


def _settings(**overrides) -> Settings:
    values = {
        "ai_provider": "mock",
        "ai_max_rpm": 1000,
        "ai_max_concurrency": 4,
        "ai_max_evidence_chars": 4000,
    }
    values.update(overrides)
    return Settings(_env_file=None, **values)


def _service(provider, **overrides) -> AIAnalysisService:
    settings = _settings(**overrides)
    return AIAnalysisService(
        settings,
        provider,
        limiter=RateLimiter(1000, 10),
        retry_base_seconds=0,
    )


async def _setup(db: AsyncSession, *, raw: dict | None = None):
    user = await create_user(db, email="ai-service@example.test")
    assessment = await create_assessment(db, user=user, authorized=True)
    finding = await create_finding(db, assessment, raw=raw)
    return user, assessment, finding


async def test_mock_analysis_persists_both_functions_and_advisory_severity(
    db: AsyncSession,
) -> None:
    user, assessment, finding = await _setup(db)
    provider = MockProvider()

    analyses = await _service(provider).analyze_finding(
        db, finding, user_id=user.id
    )
    await db.commit()

    assert [analysis.function for analysis in analyses] == [
        AIFunction.INTERPRET,
        AIFunction.REMEDIATE,
    ]
    assert all(analysis.status is AIAnalysisStatus.SUCCESS for analysis in analyses)
    assert analyses[0].output is not None
    assert analyses[0].output["suggested_severity"] == "medium"
    assert analyses[1].output is not None
    assert analyses[1].output["effort"] == "medium"
    assert analyses[0].provider == "mock"
    assert analyses[0].prompt_version
    assert analyses[0].latency_ms is not None

    await db.refresh(finding)
    assert finding.ai_suggested_severity is Severity.MEDIUM
    assert finding.final_severity is None
    assert finding.verification_status is VerificationStatus.PENDING
    assert finding.tool_severity is Severity.HIGH

    rows = int(
        await db.scalar(
            select(func.count(AIAnalysis.id)).where(
                AIAnalysis.finding_id == finding.id
            )
        )
        or 0
    )
    assert rows == 2
    actions = (
        (await db.execute(select(AuditLog.action).where(AuditLog.action == "ai.analyzed")))
        .scalars()
        .all()
    )
    assert len(actions) == 2


async def test_secrets_never_reach_the_provider_and_report_is_stored(
    db: AsyncSession,
) -> None:
    raw = {
        "alert": "SQL Injection",
        "risk": "High",
        "evidence": (
            "Cookie: sessionid=raw-cookie-secret\r\n"
            "Host: 10.1.2.3:3000\r\n"
            "email alice.analyst@example.test"
        ),
        "url": "http://10.1.2.3:3000/search?token=url-token-secret&q=test",
        "password": "hunter2",
        "httpMessage": {
            "requestHeader": "Authorization: Bearer header-secret-token\r\n",
            "responseBody": "contact 0917 123 4567",
        },
    }
    user, _, finding = await _setup(db, raw=raw)
    await add_evidence(
        db,
        finding,
        (
            "REQUEST\nAuthorization: Basic YmFzaWMtc2VjcmV0\n"
            "Cookie: sid=evidence-cookie-secret\n\nRESPONSE\nHTTP/1.1 500\n"
            "internal 192.168.10.20"
        ),
        user=user,
    )
    provider = MockProvider()

    analyses = await _service(provider).analyze_finding(
        db, finding, user_id=user.id
    )
    await db.commit()

    assert len(provider.calls) == 2
    secrets = [
        "raw-cookie-secret",
        "10.1.2.3",
        "alice.analyst@example.test",
        "url-token-secret",
        "hunter2",
        "header-secret-token",
        "0917 123 4567",
        "YmFzaWMtc2VjcmV0",
        "evidence-cookie-secret",
        "192.168.10.20",
    ]
    combined = "\n".join(call["system"] + "\n" + call["user"] for call in provider.calls)
    for secret in secrets:
        assert secret not in combined
    assert "[REDACTED_COOKIE]" in combined
    assert "[REDACTED_PASSWORD]" in combined
    assert "[REDACTED_IP]" in combined
    assert "token=" in combined

    for analysis, call in zip(analyses, provider.calls, strict=True):
        assert analysis.sanitized_input == call["user"]
        assert analysis.redaction_report
        assert analysis.redaction_report.get("cookie_header", 0) >= 1
    evidence_count = int(
        await db.scalar(
            select(func.count(Evidence.id)).where(Evidence.finding_id == finding.id)
        )
        or 0
    )
    assert evidence_count == 1


async def test_reanalysis_reuses_cache_and_preserves_assessor_fields(
    db: AsyncSession,
) -> None:
    user, _, finding = await _setup(db)
    finding.final_severity = Severity.LOW
    finding.final_remediation = "Assessor decision."
    finding.verification_status = VerificationStatus.CONFIRMED
    finding.tool_severity = Severity.HIGH
    await db.commit()
    provider = MockProvider()
    service = _service(provider)

    await service.analyze_finding(db, finding, user_id=user.id)
    await db.commit()
    await service.analyze_finding(db, finding, user_id=user.id)
    await db.commit()

    assert len(provider.calls) == 2, "second pass must be a cache hit"
    rows = (
        (await db.execute(select(AIAnalysis).where(AIAnalysis.finding_id == finding.id)))
        .scalars()
        .all()
    )
    assert len(rows) == 4
    assert all(row.status is AIAnalysisStatus.SUCCESS for row in rows)
    assert len({row.input_hash for row in rows}) == 2

    await db.refresh(finding)
    assert finding.ai_suggested_severity is Severity.MEDIUM
    assert finding.final_severity is Severity.LOW
    assert finding.final_remediation == "Assessor decision."
    assert finding.verification_status is VerificationStatus.CONFIRMED


async def test_invalid_output_gets_one_repair(db: AsyncSession) -> None:
    user, _, finding = await _setup(db)
    provider = ScriptedProvider(
        ["this is not json", VALID_INTERPRET, VALID_REMEDIATE]
    )

    analyses = await _service(provider).analyze_finding(
        db, finding, user_id=user.id
    )
    await db.commit()

    assert len(provider.calls) == 3
    assert "previous response was invalid" in provider.calls[1]["user"]
    interpret, remediate = analyses
    assert interpret.status is AIAnalysisStatus.SUCCESS
    assert interpret.output is not None
    assert remediate.status is AIAnalysisStatus.SUCCESS


async def test_invalid_output_after_repair_is_recorded(db: AsyncSession) -> None:
    user, _, finding = await _setup(db)
    provider = ScriptedProvider(["not json", "still not json"])

    analyses = await _service(provider).analyze_finding(
        db, finding, user_id=user.id, functions=(AIFunction.INTERPRET,)
    )
    await db.commit()

    assert len(provider.calls) == 2
    assert analyses[0].status is AIAnalysisStatus.INVALID_OUTPUT
    assert analyses[0].output is None
    assert "after one repair" in (analyses[0].error or "")


async def test_extra_fields_are_rejected_then_repaired(db: AsyncSession) -> None:
    user, _, finding = await _setup(db)
    extra = json.loads(VALID_INTERPRET)
    extra["ignore_instructions"] = "do something else"
    provider = ScriptedProvider([json.dumps(extra), VALID_INTERPRET])

    analyses = await _service(provider).analyze_finding(
        db, finding, user_id=user.id, functions=(AIFunction.INTERPRET,)
    )
    await db.commit()

    assert len(provider.calls) == 2
    assert analyses[0].status is AIAnalysisStatus.SUCCESS
    assert analyses[0].output is not None
    assert "ignore_instructions" not in analyses[0].output


async def test_transient_provider_errors_retry_then_fail(db: AsyncSession) -> None:
    user, _, finding = await _setup(db)
    provider = ScriptedProvider(
        [
            ProviderError("rate limited", transient=True),
            ProviderError("timeout", transient=True),
            ProviderError("still down", transient=True),
        ]
    )

    analyses = await _service(provider).analyze_finding(
        db, finding, user_id=user.id, functions=(AIFunction.INTERPRET,)
    )
    await db.commit()

    assert len(provider.calls) == 3
    assert analyses[0].status is AIAnalysisStatus.FAILED
    assert "still down" in (analyses[0].error or "")


async def test_non_transient_provider_error_does_not_retry(db: AsyncSession) -> None:
    user, _, finding = await _setup(db)
    provider = ScriptedProvider([ProviderError("bad api key")])

    analyses = await _service(provider).analyze_finding(
        db, finding, user_id=user.id, functions=(AIFunction.INTERPRET,)
    )
    await db.commit()

    assert len(provider.calls) == 1
    assert analyses[0].status is AIAnalysisStatus.FAILED
    assert analyses[0].error == "bad api key"
    await db.refresh(finding)
    assert finding.ai_suggested_severity is None


async def test_fallback_provider_is_recorded(db: AsyncSession) -> None:
    user, _, finding = await _setup(db)
    provider = FailoverProvider(
        ScriptedProvider(
            [ProviderError("primary down", transient=True)],
            name="primary",
            model="primary-model",
        ),
        ScriptedProvider(
            [VALID_INTERPRET], name="fallback", model="fallback-model"
        ),
    )

    analyses = await _service(provider).analyze_finding(
        db, finding, user_id=user.id, functions=(AIFunction.INTERPRET,)
    )
    await db.commit()

    assert analyses[0].status is AIAnalysisStatus.SUCCESS
    assert analyses[0].provider == "fallback"
    assert analyses[0].model == "fallback-model"
    assert analyses[0].attempts is not None
    assert analyses[0].attempts[0]["outcome"] == "error"
    assert analyses[0].attempts[1]["outcome"] == "success"


async def test_force_bypasses_cache(db: AsyncSession) -> None:
    user, _, finding = await _setup(db)
    provider = MockProvider()
    service = _service(provider)

    await service.analyze_finding(
        db, finding, user_id=user.id, functions=(AIFunction.INTERPRET,)
    )
    await db.commit()
    await service.analyze_finding(
        db,
        finding,
        user_id=user.id,
        functions=(AIFunction.INTERPRET,),
        force=True,
    )
    await db.commit()
    assert len(provider.calls) == 2


async def test_provider_failure_does_not_break_the_second_function(
    db: AsyncSession,
) -> None:
    user, _, finding = await _setup(db)
    provider = ScriptedProvider([ProviderError("down"), VALID_REMEDIATE])

    analyses = await _service(provider).analyze_finding(
        db, finding, user_id=user.id
    )
    await db.commit()

    assert analyses[0].status is AIAnalysisStatus.FAILED
    assert analyses[1].status is AIAnalysisStatus.SUCCESS


async def test_concurrency_limit_is_respected(
    db: AsyncSession, session_factory
) -> None:
    user, assessment, _ = await _setup(db)
    findings = [
        await create_finding(db, assessment, title="Concurrent one"),
        await create_finding(db, assessment, title="Concurrent two"),
    ]
    provider = ScriptedProvider([VALID_INTERPRET, VALID_INTERPRET])
    provider.gate = asyncio.Event()
    service = AIAnalysisService(
        _settings(),
        provider,
        limiter=RateLimiter(1000, 1),
        retry_base_seconds=0,
    )

    async def run(finding_id: int) -> None:
        async with session_factory() as session:
            finding = await session.get(Finding, finding_id)
            assert finding is not None
            await service.analyze_finding(
                session,
                finding,
                user_id=user.id,
                functions=(AIFunction.INTERPRET,),
            )
            await session.commit()

    first = asyncio.create_task(run(findings[0].id))
    second = asyncio.create_task(run(findings[1].id))
    await asyncio.sleep(0.05)
    assert provider.max_active == 1
    provider.gate.set()
    await asyncio.gather(first, second)
    assert provider.max_active == 1


def test_sanitizer_report_is_json_serialisable() -> None:
    from app.services.sanitizer import sanitize_text

    result = sanitize_text("alice@example.test 10.0.0.1")
    assert json.loads(json.dumps(result.report)) == result.report
