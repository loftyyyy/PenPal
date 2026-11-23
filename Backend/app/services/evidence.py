"""Manual evidence notes and file uploads."""

from __future__ import annotations

import asyncio
import hashlib
import uuid
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.errors import AppError
from app.db.enums import EvidenceType
from app.db.models import Evidence, Finding, User
from app.services import audit
from app.services.storage import write_data_file

ALLOWED_UPLOADS: dict[str, set[str]] = {
    ".png": {"image/png"},
    ".jpg": {"image/jpeg", "image/jpg"},
    ".jpeg": {"image/jpeg", "image/jpg"},
    ".txt": {"text/plain"},
    ".pdf": {"application/pdf"},
}


def _invalid(message: str) -> AppError:
    return AppError(422, "invalid_evidence", message)


def _looks_valid(extension: str, data: bytes) -> bool:
    if extension == ".png":
        return data.startswith(b"\x89PNG\r\n\x1a\n")
    if extension in {".jpg", ".jpeg"}:
        return data.startswith(b"\xff\xd8\xff")
    if extension == ".pdf":
        return data.startswith(b"%PDF-")
    if extension == ".txt":
        if b"\x00" in data:
            return False
        try:
            data.decode("utf-8")
        except UnicodeDecodeError:
            return False
        return True
    return False


async def add_note(
    db: AsyncSession,
    finding: Finding,
    content: str,
    user: User,
    settings: Settings,
) -> Evidence:
    text = content.strip()
    if not text:
        raise _invalid("Evidence note must not be empty")
    if len(text) > settings.evidence_text_max_chars:
        raise _invalid(
            f"Evidence note is larger than {settings.evidence_text_max_chars} characters"
        )
    evidence = Evidence(
        finding_id=finding.id,
        type=EvidenceType.NOTE,
        content=text,
        sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
        created_by=user.id,
    )
    db.add(evidence)
    await db.flush()
    await audit.record(
        db,
        "evidence.added",
        user_id=user.id,
        assessment_id=finding.assessment_id,
        entity_type="finding",
        entity_id=finding.id,
        details={"type": EvidenceType.NOTE.value, "sha256": evidence.sha256},
    )
    await db.commit()
    await db.refresh(evidence)
    return evidence


async def add_file(
    db: AsyncSession,
    finding: Finding,
    *,
    filename: str,
    content_type: str | None,
    data: bytes,
    user: User,
    settings: Settings,
) -> Evidence:
    if not data:
        raise _invalid("Uploaded file is empty")
    if len(data) > settings.max_upload_bytes:
        raise AppError(
            413,
            "file_too_large",
            f"Uploaded file is larger than {settings.max_upload_bytes} bytes",
        )
    extension = Path(filename).suffix.lower()
    allowed_types = ALLOWED_UPLOADS.get(extension)
    if allowed_types is None:
        raise _invalid(
            "Only .png, .jpg, .jpeg, .txt and .pdf evidence files are allowed"
        )
    media_type = (content_type or "").split(";", 1)[0].strip().lower()
    if media_type not in allowed_types:
        raise _invalid(
            f"Content type {media_type or 'unknown'} does not match the file extension"
        )
    if not _looks_valid(extension, data):
        raise _invalid("File content does not match the declared extension")

    stored_name = f"{uuid.uuid4().hex}{extension}"
    relative_path = (
        f"uploads/{finding.assessment_id}/{finding.id}/{stored_name}"
    )
    await asyncio.to_thread(write_data_file, settings, relative_path, data)
    evidence = Evidence(
        finding_id=finding.id,
        type=EvidenceType.FILE,
        file_path=relative_path,
        sha256=hashlib.sha256(data).hexdigest(),
        created_by=user.id,
    )
    db.add(evidence)
    await db.flush()
    await audit.record(
        db,
        "evidence.added",
        user_id=user.id,
        assessment_id=finding.assessment_id,
        entity_type="finding",
        entity_id=finding.id,
        details={
            "type": EvidenceType.FILE.value,
            "sha256": evidence.sha256,
            "filename": stored_name,
        },
    )
    await db.commit()
    await db.refresh(evidence)
    return evidence


async def list_evidence(db: AsyncSession, finding_id: int) -> list[Evidence]:
    rows = (
        (
            await db.execute(
                select(Evidence)
                .where(Evidence.finding_id == finding_id)
                .order_by(Evidence.created_at.desc(), Evidence.id.desc())
            )
        )
        .scalars()
        .all()
    )
    return list(rows)
