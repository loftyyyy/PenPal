"""Assessment and scope business logic."""

from __future__ import annotations

from collections.abc import Sequence

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.errors import ConflictError, ForbiddenError
from app.db.base import utcnow
from app.db.enums import AssessmentStatus, ScanTool
from app.db.models import Assessment, ScopeItem, User
from app.schemas.assessments import (
    AssessmentCreate,
    AssessmentUpdate,
    ScopeItemCreate,
)
from app.services import audit
from app.services.scope_guard import (
    ScopeDecision,
    ScopeGuard,
    TargetError,
    normalize_scope_value,
)


async def create_assessment(
    db: AsyncSession, payload: AssessmentCreate, user: User
) -> Assessment:
    assessment = Assessment(
        name=payload.name.strip(),
        description=payload.description,
        target_name=payload.target_name.strip(),
        target_base_url=payload.target_base_url,
        target_description=payload.target_description,
        owner_name=payload.owner_name.strip(),
        authorization_reference=payload.authorization_reference,
        hosting_environment=payload.hosting_environment,
        selected_categories=[category.value for category in payload.selected_categories],
        status=AssessmentStatus.DRAFT,
        created_by=user.id,
    )
    db.add(assessment)
    await db.flush()
    await audit.record(
        db,
        "assessment.created",
        user_id=user.id,
        assessment_id=assessment.id,
        entity_type="assessment",
        entity_id=assessment.id,
        details={"name": assessment.name, "target_name": assessment.target_name},
    )
    await db.commit()
    await db.refresh(assessment)
    return assessment


async def get_assessment(db: AsyncSession, assessment_id: int) -> Assessment | None:
    result = await db.execute(
        select(Assessment)
        .where(Assessment.id == assessment_id)
        .options(selectinload(Assessment.scope_items))
    )
    return result.scalar_one_or_none()


async def update_assessment(
    db: AsyncSession, assessment: Assessment, payload: AssessmentUpdate, user: User
) -> Assessment:
    changes = payload.model_dump(exclude_unset=True)
    if "selected_categories" in changes and changes["selected_categories"] is not None:
        changes["selected_categories"] = [
            category.value if hasattr(category, "value") else str(category)
            for category in changes["selected_categories"]
        ]
    new_status = changes.get("status")
    if new_status == AssessmentStatus.ARCHIVED:
        raise ForbiddenError("Use the archive endpoint to archive an assessment")
    if (
        new_status in {AssessmentStatus.READY, AssessmentStatus.IN_PROGRESS}
        and not assessment.authorization_confirmed
    ):
        raise ForbiddenError(
            "Authorization must be confirmed before the assessment can be ready"
        )

    previous = {
        "status": assessment.status,
        "target_base_url": assessment.target_base_url,
    }
    for key, value in changes.items():
        setattr(assessment, key, value)
    await audit.record(
        db,
        "assessment.updated",
        user_id=user.id,
        assessment_id=assessment.id,
        entity_type="assessment",
        entity_id=assessment.id,
        details={"changed_fields": sorted(changes), "previous": previous},
    )
    await db.commit()
    await db.refresh(assessment)
    return assessment


async def confirm_authorization(
    db: AsyncSession, assessment: Assessment, user: User, note: str | None
) -> Assessment:
    if not assessment.authorization_reference.strip():
        raise ForbiddenError(
            "An authorization reference must be recorded before confirmation"
        )
    if not assessment.authorization_confirmed:
        assessment.authorization_confirmed = True
        assessment.authorization_confirmed_by = user.id
        assessment.authorization_confirmed_at = utcnow()
        if assessment.status == AssessmentStatus.DRAFT:
            assessment.status = AssessmentStatus.READY
        await audit.record(
            db,
            "assessment.authorization_confirmed",
            user_id=user.id,
            assessment_id=assessment.id,
            entity_type="assessment",
            entity_id=assessment.id,
            details={"note": note, "reference": assessment.authorization_reference},
        )
        await db.commit()
        await db.refresh(assessment)
    return assessment


async def archive_assessment(
    db: AsyncSession, assessment: Assessment, user: User
) -> Assessment:
    if assessment.status != AssessmentStatus.ARCHIVED:
        previous = assessment.status
        assessment.status = AssessmentStatus.ARCHIVED
        await audit.record(
            db,
            "assessment.archived",
            user_id=user.id,
            assessment_id=assessment.id,
            entity_type="assessment",
            entity_id=assessment.id,
            details={"previous_status": previous},
        )
        await db.commit()
        await db.refresh(assessment)
    return assessment


async def list_scope_items(db: AsyncSession, assessment_id: int) -> Sequence[ScopeItem]:
    result = await db.execute(
        select(ScopeItem)
        .where(ScopeItem.assessment_id == assessment_id)
        .order_by(ScopeItem.kind, ScopeItem.value)
    )
    return result.scalars().all()


async def add_scope_item(
    db: AsyncSession, assessment: Assessment, payload: ScopeItemCreate, user: User
) -> ScopeItem:
    if assessment.status == AssessmentStatus.ARCHIVED:
        raise ForbiddenError("Archived assessments cannot be modified")
    try:
        normalized = normalize_scope_value(payload.kind, payload.value)
    except TargetError as exc:
        from app.core.errors import AppError

        raise AppError(422, "invalid_scope_value", str(exc)) from exc

    existing = await db.scalar(
        select(ScopeItem).where(
            ScopeItem.assessment_id == assessment.id,
            ScopeItem.kind == payload.kind,
            ScopeItem.value == normalized,
        )
    )
    if existing is not None:
        raise ConflictError("That scope item already exists for this assessment")

    item = ScopeItem(
        assessment_id=assessment.id,
        kind=payload.kind,
        value=normalized,
        in_scope=payload.in_scope,
        note=payload.note,
    )
    db.add(item)
    await db.flush()
    await audit.record(
        db,
        "scope.item_added",
        user_id=user.id,
        assessment_id=assessment.id,
        entity_type="scope_item",
        entity_id=item.id,
        details={"kind": item.kind, "value": item.value, "in_scope": item.in_scope},
    )
    await db.commit()
    await db.refresh(item)
    return item


async def delete_scope_item(
    db: AsyncSession, assessment: Assessment, item: ScopeItem, user: User
) -> None:
    if assessment.status == AssessmentStatus.ARCHIVED:
        raise ForbiddenError("Archived assessments cannot be modified")
    await audit.record(
        db,
        "scope.item_deleted",
        user_id=user.id,
        assessment_id=assessment.id,
        entity_type="scope_item",
        entity_id=item.id,
        details={"kind": item.kind, "value": item.value},
    )
    await db.delete(item)
    await db.commit()


async def check_scope(
    db: AsyncSession,
    assessment: Assessment,
    guard: ScopeGuard,
    target: str,
    tool: ScanTool,
    ports: Sequence[int] | None,
    user: User | None,
    *,
    context: str,
) -> ScopeDecision:
    rules = list(await list_scope_items(db, assessment.id))
    decision = await guard.check(assessment, rules, target, tool, ports)
    await audit.record(
        db,
        "scope.checked",
        user_id=user.id if user else None,
        assessment_id=assessment.id,
        entity_type="scan_target",
        details={
            "context": context,
            "tool": tool.value,
            "target": target,
            "ports": list(ports or []),
            "allowed": decision.allowed,
            "reasons": decision.reasons,
            "resolved_ips": decision.resolved_ips,
        },
    )
    await db.commit()
    return decision


def validate_ports(ports: Sequence[int]) -> list[int]:
    if len(ports) > 1000:
        raise TargetError("at most 1000 ports can be requested")
    cleaned: list[int] = []
    for port in ports:
        value = int(port)
        if not 1 <= value <= 65535:
            raise TargetError("ports must be between 1 and 65535")
        if value not in cleaned:
            cleaned.append(value)
    return cleaned
