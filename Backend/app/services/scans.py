"""Scan creation and lookup rules."""

from __future__ import annotations

from urllib.parse import urlsplit

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import (
    AppError,
    ConflictError,
    NotFoundError,
    ScopeViolationError,
)
from app.db.enums import NmapProfile, ScanStatus, ScanTool, ZapProfile
from app.db.models import Assessment, Scan, User
from app.schemas.scans import ScanCreate
from app.services import audit
from app.services.assessments import check_scope, validate_ports
from app.services.scope_guard import ScopeGuard, TargetError, normalize_target

PROFILES: dict[ScanTool, set[str]] = {
    ScanTool.NMAP: {profile.value for profile in NmapProfile},
    ScanTool.ZAP: {profile.value for profile in ZapProfile},
    ScanTool.DIG: {"default"},
    ScanTool.WHOIS: {"default"},
    ScanTool.WHATWEB: {"default"},
    ScanTool.CURL: {"default"},
    ScanTool.HTTP_CHECKS: {
        "config_baseline",
        "session",
        "access_control",
        "auth_limited",
    },
}
URL_TOOLS = {ScanTool.ZAP, ScanTool.WHATWEB, ScanTool.CURL, ScanTool.HTTP_CHECKS}
ACTIVE_STATUSES = (ScanStatus.QUEUED, ScanStatus.RUNNING)


def _invalid(message: str) -> AppError:
    return AppError(422, "invalid_scan_request", message)


def validate_profile(tool: ScanTool, profile: str) -> str:
    allowed = PROFILES[tool]
    value = profile.strip().lower()
    if value not in allowed:
        raise _invalid(
            f"profile for {tool.value} must be one of: " + ", ".join(sorted(allowed))
        )
    return value


def _explicit_url_port(raw_target: str) -> int | None:
    if "://" not in raw_target:
        return None
    try:
        return urlsplit(raw_target).port
    except ValueError:
        return None


def canonical_target(
    tool: ScanTool, raw_target: str, requested_ports: list[int]
) -> tuple[str, list[int]]:
    """Return the target stored and later re-checked by the scan manager.

    Nmap scans a host; a URL's explicit port becomes the port list so the scan
    does not silently widen to the profile's default ports. ZAP scans a URL.
    """
    try:
        normalized = normalize_target(raw_target, tool)
    except TargetError as exc:
        raise _invalid(str(exc)) from exc

    ports = list(requested_ports)
    if tool == ScanTool.NMAP:
        if not ports:
            explicit_port = _explicit_url_port(raw_target)
            if explicit_port is not None:
                ports = [explicit_port]
        return normalized.host, ports
    if tool in {ScanTool.DIG, ScanTool.WHOIS}:
        if normalized.url is not None:
            raise _invalid(f"{tool.value} targets must be a host or IP, not a URL")
        return normalized.host, ports

    if normalized.url is None:
        raise _invalid(f"{tool.value} targets must be absolute http(s) URLs")
    return normalized.url, ports


async def create_scan(
    db: AsyncSession,
    assessment: Assessment,
    payload: ScanCreate,
    user: User,
    guard: ScopeGuard,
) -> Scan:
    profile = validate_profile(payload.tool, payload.profile)
    try:
        ports = validate_ports(payload.ports)
    except TargetError as exc:
        raise _invalid(str(exc)) from exc
    target, ports = canonical_target(payload.tool, payload.target.strip(), ports)

    active = int(
        await db.scalar(
            select(func.count(Scan.id)).where(
                Scan.assessment_id == assessment.id,
                Scan.status.in_(ACTIVE_STATUSES),
            )
        )
        or 0
    )
    if active:
        raise ConflictError(
            "This assessment already has a queued or running scan; wait for it or cancel it"
        )

    decision = await check_scope(
        db,
        assessment,
        guard,
        target,
        payload.tool,
        ports,
        user,
        context="scan_request",
    )
    if not decision.allowed:
        raise ScopeViolationError(
            "Scan target rejected by the scope guard", decision.reasons
        )

    scan = Scan(
        assessment_id=assessment.id,
        tool=payload.tool,
        profile=profile,
        target=target,
        status=ScanStatus.QUEUED,
        progress=0,
        parameters={
            "ports": ports,
            "requested_target": payload.target.strip(),
            "resolved_ips": decision.resolved_ips,
            "confirm_lockout_test": payload.confirm_lockout_test,
        },
        created_by=user.id,
    )
    db.add(scan)
    await db.flush()
    await audit.record(
        db,
        "scan.requested",
        user_id=user.id,
        assessment_id=assessment.id,
        entity_type="scan",
        entity_id=scan.id,
        details={
            "tool": payload.tool.value,
            "profile": profile,
            "target": target,
            "ports": ports,
        },
    )
    await db.commit()
    await db.refresh(scan)
    return scan


async def get_scan(db: AsyncSession, scan_id: int) -> Scan:
    scan = await db.get(Scan, scan_id)
    if scan is None:
        raise NotFoundError("Scan", scan_id)
    return scan
