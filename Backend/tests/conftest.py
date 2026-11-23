# ruff: noqa: E402, I001
"""Shared pytest fixtures.

Tests never touch PostgreSQL, ZAP, Nmap or a real AI endpoint. Each test gets a
fresh SQLite database and the HTTP client talks to the ASGI app in-process.
"""

from __future__ import annotations

import os
import tempfile
from collections.abc import AsyncIterator
from pathlib import Path

TEST_DATA_DIR = Path(tempfile.mkdtemp(prefix="penpal-test-data-"))

os.environ.setdefault("ENV", "test")
os.environ.setdefault(
    "SECRET_KEY", "test-secret-key-that-is-long-enough-and-not-a-real-secret"
)
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./unused-test.db")
os.environ.setdefault("DATA_DIR", str(TEST_DATA_DIR))
os.environ.setdefault("FIRST_ADMIN_EMAIL", "admin@example.test")
os.environ.setdefault("FIRST_ADMIN_PASSWORD", "test-admin-password")
os.environ.setdefault("ZAP_API_KEY", "test-zap-key")
os.environ.setdefault("AI_PROVIDER", "mock")

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.db.base import Base
import app.db.models  # noqa: F401
from app.db.session import get_db
from app.main import create_app


@pytest.fixture(autouse=True)
def _reset_login_limiter() -> None:
    from app.services.auth import login_limiter

    login_limiter._attempts.clear()


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[AsyncEngine]:
    url = f"sqlite+aiosqlite:///{tmp_path / 'test.db'}"
    engine = create_async_engine(url)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest.fixture
async def session_factory(
    engine: AsyncEngine,
) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)


@pytest.fixture
async def db(session_factory: async_sessionmaker[AsyncSession]) -> AsyncIterator[AsyncSession]:
    async with session_factory() as session:
        yield session


@pytest.fixture
async def client(
    session_factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[AsyncClient]:
    app = create_app()

    async def override_get_db() -> AsyncIterator[AsyncSession]:
        async with session_factory() as session:
            yield session

    app.dependency_overrides[get_db] = override_get_db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as http_client:
        yield http_client
