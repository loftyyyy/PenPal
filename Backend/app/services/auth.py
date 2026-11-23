"""Authentication service: login throttling, credential check, admin bootstrap."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.security import hash_password, verify_password
from app.db.enums import Role
from app.db.models import User

logger = logging.getLogger(__name__)

# A valid argon2 hash used to equalise timing when the email does not exist.
_DUMMY_HASH = hash_password("penpal-timing-equalisation-dummy")


@dataclass
class _Attempt:
    failures: int = 0
    locked_until: float = 0.0


@dataclass
class LoginRateLimiter:
    """In-memory login backoff. Single process by design (no Redis in scope)."""

    max_attempts: int = 5
    lockout_seconds: int = 300
    _attempts: dict[str, _Attempt] = field(default_factory=dict)

    def _key(self, email: str, client_ip: str) -> str:
        return f"{email.strip().lower()}|{client_ip}"

    def retry_after(self, email: str, client_ip: str) -> int:
        attempt = self._attempts.get(self._key(email, client_ip))
        if attempt is None or attempt.locked_until <= time.monotonic():
            return 0
        return max(1, int(attempt.locked_until - time.monotonic()))

    def record_failure(self, email: str, client_ip: str) -> int:
        attempt = self._attempts.setdefault(self._key(email, client_ip), _Attempt())
        attempt.failures += 1
        if attempt.failures >= self.max_attempts:
            attempt.locked_until = time.monotonic() + self.lockout_seconds
            attempt.failures = 0
        return self.retry_after(email, client_ip)

    def reset(self, email: str, client_ip: str) -> None:
        self._attempts.pop(self._key(email, client_ip), None)


login_limiter = LoginRateLimiter()


async def authenticate(db: AsyncSession, email: str, password: str) -> User | None:
    result = await db.execute(select(User).where(User.email == email.strip().lower()))
    user = result.scalar_one_or_none()
    password_hash = user.password_hash if user is not None else _DUMMY_HASH
    valid = verify_password(password, password_hash)
    if user is None or not valid or not user.is_active:
        return None
    return user


async def bootstrap_admin(db: AsyncSession, settings: Settings) -> User | None:
    """Create the first admin from environment variables when none exists."""
    admin_count = await db.scalar(select(func.count(User.id)).where(User.role == Role.ADMIN))
    if admin_count:
        return None
    existing = await db.scalar(
        select(User).where(User.email == settings.first_admin_email.strip().lower())
    )
    if existing is not None:
        if existing.role != Role.ADMIN:
            logger.warning(
                "First admin email %s already exists as %s; not changing it",
                settings.first_admin_email,
                existing.role,
            )
        return None
    admin = User(
        email=settings.first_admin_email.strip().lower(),
        full_name="PenPal Administrator",
        password_hash=hash_password(settings.first_admin_password),
        role=Role.ADMIN,
        is_active=True,
    )
    db.add(admin)
    await db.commit()
    await db.refresh(admin)
    logger.info("Bootstrapped first administrator from environment")
    return admin
