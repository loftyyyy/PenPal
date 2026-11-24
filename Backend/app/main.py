"""FastAPI application factory and lifespan."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1 import (
    ai,
    assessments,
    audit,
    auth,
    dashboard,
    findings,
    health,
    meta,
    recon,
    reports,
    scans,
    scope,
    users,
)
from app.core.config import get_settings
from app.core.errors import install_error_handlers
from app.core.logging import configure_logging
from app.core.middleware import RequestContextMiddleware, SecurityHeadersMiddleware
from app.db.session import dispose_engine, get_session_factory
from app.services.ai.manager import shutdown_ai_manager
from app.services.auth import bootstrap_admin
from app.services.scan_manager import get_scan_manager, shutdown_scan_manager

logger = logging.getLogger(__name__)


def _ensure_data_dirs() -> None:
    settings = get_settings()
    for child in ("evidence", "reports", "uploads"):
        (settings.data_dir / child).mkdir(parents=True, exist_ok=True)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    configure_logging("DEBUG" if not settings.is_production else "INFO")
    settings.validate_for_startup()
    _ensure_data_dirs()
    logger.info("PenPal backend starting (env=%s)", settings.env)
    if settings.first_admin_email and settings.first_admin_password:
        try:
            factory = get_session_factory()
            async with factory() as db:
                await bootstrap_admin(db, settings)
        except Exception:
            logger.warning(
                "First-admin bootstrap skipped (database not ready or migrations not run)",
                exc_info=True,
            )

    manager = None
    try:
        manager = get_scan_manager()
        recovered = await manager.recover_interrupted()
        if recovered:
            logger.warning("Marked %d interrupted scan(s) as failed", recovered)
    except Exception:
        logger.warning(
            "Scan restart recovery skipped (database not ready)", exc_info=True
        )

    try:
        yield
    finally:
        try:
            await shutdown_scan_manager()
        except Exception:
            logger.warning("Scan manager shutdown failed", exc_info=True)
        try:
            await shutdown_ai_manager()
        except Exception:
            logger.warning("AI manager shutdown failed", exc_info=True)
        await dispose_engine()
        logger.info("PenPal backend stopped")


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="PenPal API",
        version="0.1.0",
        description=(
            "AI-assisted security assessment platform. Human verification is mandatory: "
            "AI output is advisory and only assessor-confirmed findings appear in reports."
        ),
        lifespan=lifespan,
        docs_url=None if settings.is_production else "/docs",
        redoc_url=None if settings.is_production else "/redoc",
        openapi_url=None if settings.is_production else "/openapi.json",
        openapi_tags=[
            {"name": "Health", "description": "Liveness and dependency checks"},
            {"name": "Metadata", "description": "Server-side constants such as the risk matrix"},
            {"name": "Auth", "description": "Login and current user"},
            {"name": "Users", "description": "Administrator user management"},
            {"name": "Assessments", "description": "Assessment registration and authorization"},
            {"name": "Scope", "description": "In-scope and out-of-scope rules; dry-run checks"},
            {"name": "Scans", "description": "Nmap and ZAP scan lifecycle"},
            {"name": "Recon", "description": "Aggregated Nmap reconnaissance"},
            {"name": "Findings", "description": "Findings, verification and evidence"},
            {"name": "AI", "description": "Advisory AI interpretation and remediation"},
            {"name": "Dashboard", "description": "Aggregated assessment metrics"},
            {"name": "Reports", "description": "HTML and PDF report generation"},
            {"name": "Audit", "description": "Append-only audit trail"},
        ],
    )

    install_error_handlers(app)

    app.add_middleware(RequestContextMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
        expose_headers=["X-Request-ID", "Content-Disposition"],
    )

    app.include_router(health.router, prefix=settings.api_prefix)
    app.include_router(meta.router, prefix=settings.api_prefix)
    app.include_router(auth.router, prefix=settings.api_prefix)
    app.include_router(users.router, prefix=settings.api_prefix)
    app.include_router(assessments.router, prefix=settings.api_prefix)
    app.include_router(scope.router, prefix=settings.api_prefix)
    app.include_router(scans.router, prefix=settings.api_prefix)
    app.include_router(recon.router, prefix=settings.api_prefix)
    app.include_router(findings.router, prefix=settings.api_prefix)
    app.include_router(ai.router, prefix=settings.api_prefix)
    app.include_router(dashboard.router, prefix=settings.api_prefix)
    app.include_router(audit.router, prefix=settings.api_prefix)
    app.include_router(reports.router, prefix=settings.api_prefix)
    return app


app = create_app()
