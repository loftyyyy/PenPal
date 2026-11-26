"""Target ownership verification tokens and well-known file checks."""

from __future__ import annotations

import secrets
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlsplit

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import AppError, ConflictError, ForbiddenError, NotFoundError
from app.db.base import utcnow
from app.db.enums import AssessmentStatus, Role
from app.db.models import Assessment, AuthorizationFile, User
from app.schemas.authorization_files import (
    AuthorizationFileCreate,
    AuthorizationFileOut,
    AuthorizationFileStatus,
)
from app.services import audit

FETCH_TIMEOUT_SECONDS = 5.0
MAX_VERIFICATION_BYTES = 4096

FetchResult = tuple[int, str]
Fetcher = Callable[[str], Awaitable[FetchResult]]


async def fetch_verification_content(url: str) -> FetchResult:
    async with httpx.AsyncClient(
        timeout=FETCH_TIMEOUT_SECONDS,
        follow_redirects=False,
        headers={"User-Agent": "PenPal-Authorization-Verifier/0.1"},
    ) as client, client.stream("GET", url) as response:
        chunks: list[bytes] = []
        total = 0
        async for chunk in response.aiter_bytes():
            remaining = MAX_VERIFICATION_BYTES - total
            if remaining <= 0:
                break
            chunks.append(chunk[:remaining])
            total += len(chunks[-1])
            if total >= MAX_VERIFICATION_BYTES:
                break
        return response.status_code, b"".join(chunks).decode(
            "utf-8", errors="replace"
        )


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def _status(record: AuthorizationFile) -> AuthorizationFileStatus:
    if record.revoked_at is not None:
        return "revoked"
    if _aware(record.expires_at) <= utcnow():
        return "expired"
    if record.verified_at is not None:
        return "verified"
    return "pending"


def to_out(record: AuthorizationFile) -> AuthorizationFileOut:
    target = record.target.rstrip("/")
    return AuthorizationFileOut(
        id=record.id,
        assessment_id=record.assessment_id,
        created_by=record.created_by,
        target=record.target,
        token=record.token,
        content=record.token,
        verification_path=record.verification_path,
        verification_url=f"{target}{record.verification_path}",
        status=_status(record),
        expires_at=record.expires_at,
        revoked_at=record.revoked_at,
        verified_at=record.verified_at,
        last_checked_at=record.last_checked_at,
        failure_reason=record.failure_reason,
        created_at=record.created_at,
        updated_at=record.updated_at,
    )


def ensure_can_manage(assessment: Assessment, user: User) -> None:
    if user.role != Role.ADMIN and assessment.created_by != user.id:
        raise ForbiddenError(
            "Only the assessment creator or an administrator can manage "
            "authorization files for this target"
        )


def _target_origin(assessment: Assessment) -> str:
    raw = (assessment.target_base_url or "").strip()
    if not raw:
        raise AppError(
            422,
            "authorization_target_required",
            "Set the assessment target base URL before creating an authorization file",
        )
    try:
        parts = urlsplit(raw)
        port = parts.port
    except ValueError as exc:
        raise AppError(
            422, "authorization_target_required", "Assessment target URL is invalid"
        ) from exc
    if (
        parts.scheme.lower() not in {"http", "https"}
        or not parts.hostname
        or parts.username is not None
        or parts.password is not None
    ):
        raise AppError(
            422,
            "authorization_target_required",
            "Assessment target must be an absolute http(s) URL without userinfo",
        )
    host = parts.hostname
    if ":" in host:
        host = f"[{host}]"
    netloc = f"{host}:{port}" if port is not None else host
    return f"{parts.scheme.lower()}://{netloc}"


async def _record_or_404(db: AsyncSession, file_id: int) -> AuthorizationFile:
    record = await db.get(AuthorizationFile, file_id)
    if record is None:
        raise NotFoundError("Authorization file", file_id)
    return record


async def _assessment_for(
    db: AsyncSession, record: AuthorizationFile, user: User
) -> Assessment:
    assessment = await db.get(Assessment, record.assessment_id)
    if assessment is None:
        raise NotFoundError("Assessment", record.assessment_id)
    ensure_can_manage(assessment, user)
    return assessment


async def create_authorization_file(
    db: AsyncSession,
    assessment: Assessment,
    user: User,
    payload: AuthorizationFileCreate,
) -> AuthorizationFile:
    ensure_can_manage(assessment, user)
    if assessment.status == AssessmentStatus.ARCHIVED:
        raise ConflictError("Archived assessments cannot create authorization files")
    target = _target_origin(assessment)
    now = utcnow()

    active = (
        (
            await db.execute(
                select(AuthorizationFile).where(
                    AuthorizationFile.assessment_id == assessment.id,
                    AuthorizationFile.target == target,
                    AuthorizationFile.revoked_at.is_(None),
                )
            )
        )
        .scalars()
        .all()
    )
    replaced: list[int] = []
    for previous in active:
        previous.revoked_at = now
        previous.failure_reason = "replaced by a newer authorization file"
        replaced.append(previous.id)

    token = ""
    for _ in range(5):
        candidate = secrets.token_urlsafe(32)
        exists = await db.scalar(
            select(AuthorizationFile.id).where(AuthorizationFile.token == candidate)
        )
        if exists is None:
            token = candidate
            break
    if not token:  # pragma: no cover - astronomically unlikely
        raise AppError(500, "token_generation_failed", "Could not allocate a token")

    record = AuthorizationFile(
        assessment_id=assessment.id,
        created_by=user.id,
        target=target,
        token=token,
        verification_path=payload.verification_path,
        expires_at=now + timedelta(hours=payload.expires_in_hours),
    )
    db.add(record)
    await db.flush()
    await audit.record(
        db,
        "authorization_file.created",
        user_id=user.id,
        assessment_id=assessment.id,
        entity_type="authorization_file",
        entity_id=record.id,
        details={
            "target": target,
            "verification_path": record.verification_path,
            "expires_at": record.expires_at.isoformat(),
            "replaced_ids": replaced,
            "token_prefix": token[:8],
        },
    )
    await db.commit()
    await db.refresh(record)
    return record


async def list_authorization_files(
    db: AsyncSession, assessment: Assessment, user: User
) -> list[AuthorizationFile]:
    ensure_can_manage(assessment, user)
    return list(
        (
            await db.execute(
                select(AuthorizationFile)
                .where(AuthorizationFile.assessment_id == assessment.id)
                .order_by(AuthorizationFile.created_at.desc(), AuthorizationFile.id.desc())
            )
        )
        .scalars()
        .all()
    )


async def get_authorization_file(
    db: AsyncSession, file_id: int, user: User
) -> AuthorizationFile:
    record = await _record_or_404(db, file_id)
    await _assessment_for(db, record, user)
    return record


async def revoke_authorization_file(
    db: AsyncSession, file_id: int, user: User
) -> AuthorizationFile:
    record = await _record_or_404(db, file_id)
    assessment = await _assessment_for(db, record, user)
    if record.revoked_at is not None:
        raise ConflictError("Authorization file is already revoked")
    record.revoked_at = utcnow()
    record.failure_reason = "revoked by assessor"
    await audit.record(
        db,
        "authorization_file.revoked",
        user_id=user.id,
        assessment_id=assessment.id,
        entity_type="authorization_file",
        entity_id=record.id,
        details={"target": record.target, "token_prefix": record.token[:8]},
    )
    await db.commit()
    await db.refresh(record)
    return record


async def _fail(
    db: AsyncSession,
    record: AuthorizationFile,
    assessment: Assessment,
    user: User,
    *,
    code: str,
    message: str,
    reason: str,
    status_code: int = 422,
    details: dict[str, Any] | None = None,
) -> AppError:
    record.last_checked_at = utcnow()
    record.failure_reason = reason
    await audit.record(
        db,
        "authorization_file.verification_failed",
        user_id=user.id,
        assessment_id=assessment.id,
        entity_type="authorization_file",
        entity_id=record.id,
        details={"target": record.target, "reason": reason},
    )
    return AppError(status_code, code, message, details)


async def verify_authorization_file(
    db: AsyncSession,
    file_id: int,
    user: User,
    *,
    fetcher: Fetcher | None = None,
) -> AuthorizationFile:
    record = await _record_or_404(db, file_id)
    assessment = await _assessment_for(db, record, user)
    status = _status(record)
    if status == "revoked":
        raise AppError(
            409, "authorization_file_revoked", "Authorization file is revoked"
        )
    if status == "expired":
        raise AppError(
            409, "authorization_file_expired", "Authorization file has expired"
        )

    url = f"{record.target.rstrip('/')}{record.verification_path}"
    record.last_checked_at = utcnow()
    try:
        status_code, body = await (fetcher or fetch_verification_content)(url)
    except httpx.HTTPError as exc:
        error = await _fail(
            db,
            record,
            assessment,
            user,
            code="authorization_file_unreachable",
            message="Could not fetch the verification file from the target",
            reason=f"fetch failed: {exc.__class__.__name__}",
            details={"url": url},
        )
        await db.commit()
        raise error from exc

    if status_code != 200:
        error = await _fail(
            db,
            record,
            assessment,
            user,
            code="authorization_file_unavailable",
            message="Verification file is not available at the configured path",
            reason=f"remote HTTP {status_code}",
            details={"url": url, "status": status_code},
        )
        await db.commit()
        raise error

    if body.strip() != record.token:
        error = await _fail(
            db,
            record,
            assessment,
            user,
            code="authorization_file_mismatch",
            message="Verification file does not contain the expected token",
            reason="token mismatch",
            details={"url": url},
        )
        await db.commit()
        raise error

    record.verified_at = utcnow()
    record.failure_reason = None
    await audit.record(
        db,
        "authorization_file.verified",
        user_id=user.id,
        assessment_id=assessment.id,
        entity_type="authorization_file",
        entity_id=record.id,
        details={"target": record.target, "url": url},
    )
    await db.commit()
    await db.refresh(record)
    return record
