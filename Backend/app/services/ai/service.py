"""Run the advisory AI functions and persist every attempt."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import random
from collections import deque
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from pydantic import BaseModel, ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.errors import AppError
from app.db.enums import (
    SEVERITY_ORDER,
    AIAnalysisStatus,
    AIFunction,
    EvidenceType,
    Severity,
    VerificationStatus,
)
from app.db.models import AIAnalysis, Assessment, Evidence, Finding, Scan
from app.services import audit
from app.services.ai.base import AIProvider, ProviderError, ProviderResult
from app.services.ai.failover import FailoverProvider
from app.services.ai.mock import MockProvider
from app.services.ai.openai_compat import OpenAICompatProvider
from app.services.ai.prompts import (
    PROMPT_VERSION,
    build_repair_prompt,
    build_system_prompt,
    build_user_prompt,
)
from app.services.ai.schemas import InterpretOutput, RemediateOutput, SummaryOutput
from app.services.sanitizer import sanitize_data, sanitize_text

logger = logging.getLogger(__name__)

OUTPUT_SCHEMAS: dict[AIFunction, type[BaseModel]] = {
    AIFunction.INTERPRET: InterpretOutput,
    AIFunction.REMEDIATE: RemediateOutput,
    AIFunction.SUMMARY: SummaryOutput,
}
EVIDENCE_ROWS = 5
RAW_FIELD_MAX_CHARS = 2000


class OutputError(ValueError):
    """The provider returned text that does not match the schema."""


class RateLimiter:
    """Process-wide requests-per-minute and concurrency limiter."""

    def __init__(self, max_rpm: int, max_concurrency: int) -> None:
        self.max_rpm = max(1, max_rpm)
        self._semaphore = asyncio.Semaphore(max(1, max_concurrency))
        self._slots: deque[float] = deque()
        self._lock = asyncio.Lock()

    async def __aenter__(self) -> None:
        await self._semaphore.acquire()
        try:
            await self._wait_for_slot()
        except BaseException:
            self._semaphore.release()
            raise

    async def __aexit__(self, *_exc_info: object) -> None:
        self._semaphore.release()

    async def _wait_for_slot(self) -> None:
        async with self._lock:
            loop = asyncio.get_running_loop()
            now = loop.time()
            while self._slots and now - self._slots[0] >= 60:
                self._slots.popleft()
            if len(self._slots) >= self.max_rpm:
                wait = 60 - (now - self._slots[0])
                if wait > 0:
                    await asyncio.sleep(wait)
                now = loop.time()
                while self._slots and now - self._slots[0] >= 60:
                    self._slots.popleft()
            self._slots.append(now)


@dataclass
class _Prompt:
    system: str
    user: str
    payload_json: str
    redaction_report: dict[str, int]


def build_provider(settings: Settings) -> AIProvider:
    if settings.ai_provider == "mock":
        return MockProvider()
    if settings.ai_provider == "openai_compat":
        primary = OpenAICompatProvider(settings)
        if settings.ai_fallback_base_url:
            fallback_settings = settings.model_copy(
                update={
                    "ai_base_url": settings.ai_fallback_base_url,
                    "ai_api_key": settings.ai_fallback_api_key,
                    "ai_model": settings.ai_fallback_model,
                    "ai_extra_body": settings.ai_fallback_extra_body,
                    "ai_timeout_seconds": settings.ai_fallback_timeout_seconds,
                }
            )
            return FailoverProvider(
                primary,
                OpenAICompatProvider(fallback_settings),
                fallback_max_tokens=settings.ai_fallback_max_tokens,
            )
        return primary
    raise ProviderError(f"Unknown AI_PROVIDER: {settings.ai_provider}")


def _relative_endpoint(value: str | None) -> str | None:
    if not value:
        return None
    try:
        parts = urlsplit(value)
    except ValueError:
        return value
    if not parts.scheme or not parts.hostname:
        return value
    return parts.path or "/"


def _trim_raw(raw: dict[str, Any]) -> dict[str, Any]:
    """Drop the full HTTP exchange; it is captured as evidence separately."""
    trimmed = {
        key: value
        for key, value in raw.items()
        if key not in {"httpMessage", "requestBody", "responseBody"}
    }
    return trimmed


def _merge_reports(*reports: dict[str, int]) -> dict[str, int]:
    merged: dict[str, int] = {}
    for report in reports:
        for kind, amount in report.items():
            merged[kind] = merged.get(kind, 0) + amount
    return dict(sorted(merged.items()))


def _parse_output(function: AIFunction, content: str) -> BaseModel:
    text = content.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        text = "\n".join(lines).strip()
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise OutputError("response is not a JSON object")
    try:
        payload = json.loads(text[start : end + 1])
    except ValueError as exc:
        raise OutputError(f"response is not valid JSON: {exc}") from exc
    schema = OUTPUT_SCHEMAS[function]
    try:
        return schema.model_validate(payload)
    except ValidationError as exc:
        first = exc.errors()[0] if exc.errors() else {}
        location = ".".join(str(part) for part in first.get("loc", []))
        message = first.get("msg", "schema validation failed")
        raise OutputError(f"{location or 'payload'}: {message}") from exc


class AIAnalysisService:
    def __init__(
        self,
        settings: Settings,
        provider: AIProvider,
        *,
        limiter: RateLimiter | None = None,
        retry_base_seconds: float = 1.0,
        max_attempts: int = 3,
    ) -> None:
        self.settings = settings
        self.provider = provider
        self.limiter = limiter or RateLimiter(
            settings.ai_max_rpm, settings.ai_max_concurrency
        )
        self.retry_base_seconds = max(0.0, retry_base_seconds)
        self.max_attempts = max(1, max_attempts)

    async def analyze_finding(
        self,
        db: AsyncSession,
        finding: Finding,
        *,
        user_id: int | None = None,
        functions: tuple[AIFunction, ...] = (
            AIFunction.INTERPRET,
            AIFunction.REMEDIATE,
        ),
        force: bool = False,
    ) -> list[AIAnalysis]:
        analyses: list[AIAnalysis] = []
        for function in functions:
            analysis = await self._run_function(
                db, finding, function, user_id=user_id, force=force
            )
            analyses.append(analysis)
        return analyses

    async def _run_function(
        self,
        db: AsyncSession,
        finding: Finding,
        function: AIFunction,
        *,
        user_id: int | None,
        force: bool = False,
    ) -> AIAnalysis:
        prompt = await self._build_prompt(db, finding, function)
        return await self._execute_prompt(
            db,
            prompt,
            function=function,
            finding=finding,
            assessment_id=finding.assessment_id,
            user_id=user_id,
            force=force,
        )

    async def analyze_assessment_summary(
        self,
        db: AsyncSession,
        assessment: Assessment,
        *,
        user_id: int | None = None,
        force: bool = False,
    ) -> AIAnalysis:
        prompt = await self._build_summary_prompt(db, assessment)
        return await self._execute_prompt(
            db,
            prompt,
            function=AIFunction.SUMMARY,
            finding=None,
            assessment_id=assessment.id,
            user_id=user_id,
            force=force,
        )

    async def _execute_prompt(
        self,
        db: AsyncSession,
        prompt: _Prompt,
        *,
        function: AIFunction,
        finding: Finding | None,
        assessment_id: int,
        user_id: int | None,
        force: bool = False,
    ) -> AIAnalysis:
        # Provider-agnostic cache key: a successful result from either provider is reused.
        digest = hashlib.sha256(
            f"{PROMPT_VERSION}|{prompt.user}".encode()
        ).hexdigest()

        cached = None
        if not force:
            cached = await db.scalar(
                select(AIAnalysis)
                .where(
                    AIAnalysis.input_hash == digest,
                    AIAnalysis.status == AIAnalysisStatus.SUCCESS,
                )
                .order_by(AIAnalysis.id.desc())
                .limit(1)
            )
        if cached is not None and isinstance(cached.output, dict):
            analysis = AIAnalysis(
                finding_id=finding.id if finding else None,
                assessment_id=assessment_id,
                function=function,
                provider=cached.provider,
                model=cached.model,
                prompt_version=PROMPT_VERSION,
                input_hash=digest,
                sanitized_input=prompt.user,
                output=cached.output,
                status=AIAnalysisStatus.SUCCESS,
                latency_ms=0,
                redaction_report=prompt.redaction_report,
            )
            db.add(analysis)
            await db.flush()
            if finding is not None:
                await self._apply_interpretation(finding, function, cached.output)
            await self._audit(db, assessment_id, finding, analysis, user_id)
            return analysis

        system = build_system_prompt(function)
        user = prompt.user
        redaction_report = prompt.redaction_report
        started = asyncio.get_running_loop().time()
        result: ProviderResult | None = None
        output: BaseModel | None = None
        error: str | None = None
        attempts: list[dict[str, Any]] = []
        status = AIAnalysisStatus.SUCCESS

        try:
            result = await self._call_provider(system, user)
            try:
                output = _parse_output(function, result.content)
            except OutputError as first_error:
                previous = sanitize_text(result.content, max_chars=4000)
                repair_user = build_repair_prompt(
                    function,
                    prompt.payload_json,
                    previous.text,
                    str(first_error),
                )
                user = repair_user
                redaction_report = _merge_reports(
                    redaction_report, previous.report
                )
                result = await self._call_provider(system, repair_user)
                try:
                    output = _parse_output(function, result.content)
                except OutputError as second_error:
                    raise OutputError(
                        f"invalid output after one repair: {second_error}"
                    ) from second_error
        except (ProviderError, OutputError) as exc:
            status = (
                AIAnalysisStatus.INVALID_OUTPUT
                if isinstance(exc, OutputError)
                else AIAnalysisStatus.FAILED
            )
            error = str(exc)[:2000]
            attempts = list(getattr(exc, "attempts", None) or [])
        except Exception as exc:  # pragma: no cover - defensive
            logger.exception(
                "Unexpected AI failure for %s",
                f"finding {finding.id}" if finding else f"assessment {assessment_id}",
            )
            status = AIAnalysisStatus.FAILED
            error = f"unexpected AI failure: {type(exc).__name__}"

        if result is not None:
            attempts = list(result.attempts or [])
        latency_ms = int(
            max(0.0, (asyncio.get_running_loop().time() - started) * 1000)
        )
        analysis = AIAnalysis(
            finding_id=finding.id if finding else None,
            assessment_id=assessment_id,
            function=function,
            provider=(result.provider if result else None) or self.provider.name,
            model=(result.model if result else None) or self.provider.model,
            prompt_version=PROMPT_VERSION,
            input_hash=digest,
            sanitized_input=user,
            output=output.model_dump(mode="json") if output is not None else None,
            status=status,
            error=error,
            latency_ms=latency_ms,
            prompt_tokens=result.prompt_tokens if result else None,
            completion_tokens=result.completion_tokens if result else None,
            redaction_report=redaction_report,
            attempts=attempts or None,
        )
        db.add(analysis)
        await db.flush()
        if finding is not None and output is not None:
            await self._apply_interpretation(finding, function, analysis.output or {})
        await self._audit(db, assessment_id, finding, analysis, user_id)
        return analysis

    async def _call_provider(self, system: str, user: str) -> ProviderResult:
        for attempt in range(self.max_attempts):
            try:
                async with self.limiter:
                    return await self.provider.complete_json(
                        system, user, max_tokens=self.settings.ai_max_tokens
                    )
            except ProviderError as exc:
                if not exc.transient or attempt == self.max_attempts - 1:
                    raise
                delay = self.retry_base_seconds * (2**attempt)
                if delay:
                    # Jitter is only to avoid a retry stampede; not security-sensitive.
                    await asyncio.sleep(
                        delay + random.uniform(0, delay * 0.3)  # noqa: S311
                    )
        raise ProviderError("AI request failed")  # pragma: no cover - loop exits

    async def _apply_interpretation(
        self, finding: Finding, function: AIFunction, output: dict[str, Any]
    ) -> None:
        if function != AIFunction.INTERPRET:
            return
        value = output.get("suggested_severity")
        if isinstance(value, str):
            finding.ai_suggested_severity = Severity(value)

    async def _audit(
        self,
        db: AsyncSession,
        assessment_id: int,
        finding: Finding | None,
        analysis: AIAnalysis,
        user_id: int | None,
    ) -> None:
        await audit.record(
            db,
            "ai.analyzed",
            user_id=user_id,
            assessment_id=assessment_id,
            entity_type="finding" if finding else "assessment",
            entity_id=finding.id if finding else assessment_id,
            details={
                "function": analysis.function.value,
                "status": analysis.status.value,
                "provider": analysis.provider,
                "model": analysis.model,
            },
        )

    async def _build_prompt(
        self, db: AsyncSession, finding: Finding, function: AIFunction
    ) -> _Prompt:
        assessment = await db.get(Assessment, finding.assessment_id)
        evidence_rows = (
            (
                await db.execute(
                    select(Evidence)
                    .where(Evidence.finding_id == finding.id)
                    .order_by(Evidence.created_at.desc(), Evidence.id.desc())
                    .limit(EVIDENCE_ROWS)
                )
            )
            .scalars()
            .all()
        )
        snippets: list[str] = []
        for evidence in evidence_rows:
            if evidence.type is EvidenceType.FILE:
                snippets.append(f"[file evidence] {evidence.file_path or 'unavailable'}")
                continue
            if evidence.content:
                result = sanitize_text(
                    evidence.content,
                    max_chars=max(500, self.settings.ai_max_evidence_chars),
                )
                snippets.append(f"[{evidence.type.value}] {result.text}")
        evidence_text = "\n\n---\n\n".join(snippets)
        evidence_result = sanitize_text(
            evidence_text,
            max_chars=self.settings.ai_max_evidence_chars,
        )

        raw_payload, raw_report = sanitize_data(
            _trim_raw(finding.raw or {}), max_chars=RAW_FIELD_MAX_CHARS
        )
        payload, payload_report = sanitize_data(
            {
                "finding": {
                    "title": finding.title,
                    "description": finding.description,
                    "source": finding.source.value,
                    "category": finding.category.value,
                    "owasp_category": finding.owasp_category,
                    "cwe": finding.cwe,
                    "affected_path": _relative_endpoint(finding.affected_url),
                    "http_method": finding.http_method,
                    "parameter": finding.parameter,
                    "tool_severity": (
                        finding.tool_severity.value if finding.tool_severity else None
                    ),
                    "tool_confidence": finding.tool_confidence,
                },
                "assessment": {
                    "name": assessment.name if assessment else None,
                    "selected_categories": (
                        assessment.selected_categories if assessment else []
                    ),
                },
                "tool_payload": raw_payload,
                "evidence": evidence_result.text,
            },
            max_chars=None,
        )
        payload_json = json.dumps(payload, indent=2, sort_keys=True, default=str)
        user = build_user_prompt(function, payload_json)
        return _Prompt(
            system=build_system_prompt(function),
            user=user,
            payload_json=payload_json,
            redaction_report=_merge_reports(
                payload_report, raw_report, evidence_result.report
            ),
        )

    async def _build_summary_prompt(
        self, db: AsyncSession, assessment: Assessment
    ) -> _Prompt:
        confirmed = (
            (
                await db.execute(
                    select(Finding).where(
                        Finding.assessment_id == assessment.id,
                        Finding.verification_status == VerificationStatus.CONFIRMED,
                    )
                )
            )
            .scalars()
            .all()
        )
        if not confirmed:
            raise AppError(
                409,
                "no_confirmed_findings",
                "No confirmed findings are available to summarize",
            )
        confirmed = sorted(
            confirmed,
            key=lambda finding: (
                -(
                    SEVERITY_ORDER[finding.final_severity]
                    if finding.final_severity
                    else 0
                ),
                finding.id,
            ),
        )
        scans = (
            (
                await db.execute(
                    select(Scan)
                    .where(Scan.assessment_id == assessment.id)
                    .order_by(Scan.created_at.asc(), Scan.id.asc())
                )
            )
            .scalars()
            .all()
        )
        severity_counts = {
            severity.value: 0 for severity in SEVERITY_ORDER
        }
        category_counts: dict[str, int] = {}
        for finding in confirmed:
            category_counts[finding.category.value] = (
                category_counts.get(finding.category.value, 0) + 1
            )
            if finding.final_severity is not None:
                severity_counts[finding.final_severity.value] += 1

        payload, payload_report = sanitize_data(
            {
                "assessment": {
                    "name": assessment.name,
                    "target_name": assessment.target_name,
                    "selected_categories": assessment.selected_categories,
                },
                "confirmed_counts": {
                    "by_severity": severity_counts,
                    "by_category": category_counts,
                    "total": len(confirmed),
                },
                "findings": [
                    {
                        "title": finding.title,
                        "category": finding.category.value,
                        "final_severity": (
                            finding.final_severity.value
                            if finding.final_severity
                            else None
                        ),
                        "affected_path": _relative_endpoint(finding.affected_url),
                        "final_remediation_first_line": (
                            (finding.final_remediation or "").strip().splitlines()[0][:300]
                            if (finding.final_remediation or "").strip()
                            else None
                        ),
                    }
                    for finding in confirmed
                ],
                "scans": [
                    {
                        "tool": scan.tool.value,
                        "profile": scan.profile,
                        "tool_version": scan.tool_version,
                    }
                    for scan in scans
                ],
            },
            max_chars=RAW_FIELD_MAX_CHARS,
        )
        payload_json = json.dumps(payload, indent=2, sort_keys=True, default=str)
        user = build_user_prompt(AIFunction.SUMMARY, payload_json)
        return _Prompt(
            system=build_system_prompt(AIFunction.SUMMARY),
            user=user,
            payload_json=payload_json,
            redaction_report=payload_report,
        )


def get_ai_service(settings: Settings) -> AIAnalysisService:
    return AIAnalysisService(settings, build_provider(settings))


__all__ = [
    "AIAnalysisService",
    "OutputError",
    "RateLimiter",
    "build_provider",
    "get_ai_service",
]
