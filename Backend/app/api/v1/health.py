"""Liveness and dependency health."""

from __future__ import annotations

import shutil

import httpx
from fastapi import APIRouter, Depends
from sqlalchemy import text

from app.core.config import Settings, get_settings
from app.core.deps import DbSession
from app.schemas.health import DependenciesResponse, DependencyStatus, HealthResponse

router = APIRouter(tags=["Health"])


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Liveness check",
    description="Returns OK when the API process is running.",
)
async def health() -> HealthResponse:
    return HealthResponse(status="ok", service="penpal-backend", version="0.1.0")


@router.get(
    "/health/dependencies",
    response_model=DependenciesResponse,
    summary="Dependency readiness",
    description=(
        "Checks the database, ZAP daemon, Nmap binary and AI configuration. "
        "Never returns secret values."
    ),
)
async def dependencies(
    db: DbSession,
    settings: Settings = Depends(get_settings),
) -> DependenciesResponse:
    checks: list[DependencyStatus] = []

    try:
        await db.execute(text("SELECT 1"))
        checks.append(DependencyStatus(name="database", ok=True, detail="reachable"))
    except Exception:
        checks.append(DependencyStatus(name="database", ok=False, detail="unreachable"))

    nmap_path = shutil.which(settings.nmap_binary)
    checks.append(
        DependencyStatus(
            name="nmap",
            ok=nmap_path is not None,
            detail="binary present" if nmap_path else "binary not found on PATH",
        )
    )

    if settings.ai_provider == "mock":
        checks.append(
            DependencyStatus(name="ai_provider", ok=True, detail="mock provider configured")
        )
    elif settings.ai_provider == "openai_compat":
        configured = bool(settings.ai_base_url and settings.ai_model)
        checks.append(
            DependencyStatus(
                name="ai_provider",
                ok=configured,
                detail="openai-compatible endpoint configured" if configured else "not configured",
            )
        )
    else:
        checks.append(
            DependencyStatus(
                name="ai_provider", ok=False, detail="unknown AI_PROVIDER value"
            )
        )

    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            response = await client.get(
                f"{settings.zap_base_url.rstrip('/')}/JSON/core/view/version/",
                params={"apikey": settings.zap_api_key},
            )
            response.raise_for_status()
        checks.append(DependencyStatus(name="zap", ok=True, detail="daemon reachable"))
    except Exception:
        checks.append(DependencyStatus(name="zap", ok=False, detail="daemon unreachable"))

    overall = "ok" if all(check.ok for check in checks) else "degraded"
    return DependenciesResponse(status=overall, dependencies=checks)
