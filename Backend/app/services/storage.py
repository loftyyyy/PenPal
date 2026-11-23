"""Safe file storage for evidence and reports."""

from __future__ import annotations

import hashlib
from pathlib import Path

from app.core.config import Settings


class UnsafePathError(ValueError):
    pass


def resolve_data_path(settings: Settings, relative_path: str) -> Path:
    """Resolve a stored relative path, refusing anything outside DATA_DIR."""
    base = settings.data_dir.resolve()
    candidate = (base / relative_path).resolve()
    if not candidate.is_relative_to(base):
        raise UnsafePathError("path escapes DATA_DIR")
    return candidate


def write_data_file(settings: Settings, relative_path: str, data: bytes) -> Path:
    path = resolve_data_path(settings, relative_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def read_data_file(settings: Settings, relative_path: str, max_bytes: int | None = None) -> bytes:
    path = resolve_data_path(settings, relative_path)
    if max_bytes is not None and path.stat().st_size > max_bytes:
        raise UnsafePathError("file is larger than the allowed limit")
    return path.read_bytes()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
