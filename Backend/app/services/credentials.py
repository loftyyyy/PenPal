"""Encrypt write-only test-account passwords with Fernet."""

from __future__ import annotations

import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken

from app.core.config import Settings
from app.core.errors import AppError


def _fernet(settings: Settings) -> Fernet:
    key = settings.credentials_key.strip()
    if key:
        try:
            return Fernet(key.encode("ascii"))
        except (ValueError, UnicodeEncodeError) as exc:
            raise AppError(
                500,
                "credentials_key_invalid",
                "CREDENTIALS_KEY is not a valid Fernet key",
            ) from exc
    # Development/test fallback: derive a stable key from SECRET_KEY. Production
    # startup refuses to run without an explicit CREDENTIALS_KEY.
    derived = base64.urlsafe_b64encode(
        hashlib.sha256(settings.secret_key.encode("utf-8")).digest()
    )
    return Fernet(derived)


def encrypt_secret(value: str, settings: Settings) -> str:
    return _fernet(settings).encrypt(value.encode("utf-8")).decode("ascii")


def decrypt_secret(value: str, settings: Settings) -> str:
    try:
        return _fernet(settings).decrypt(value.encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError) as exc:
        raise AppError(
            500,
            "credentials_key_mismatch",
            "Stored test-account credentials cannot be decrypted",
        ) from exc
