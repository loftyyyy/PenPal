"""Aggregated reconnaissance read endpoint."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from app.core.config import Settings, get_settings
from app.core.deps import CurrentUser, DbSession, get_assessment_or_404
from app.schemas.recon import ReconOut
from app.services.recon import build_recon

router = APIRouter(prefix="/assessments/{assessment_id}", tags=["Recon"])


@router.get(
    "/recon",
    response_model=ReconOut,
    summary="Aggregated hosts, ports and services from completed Nmap scans",
    description=(
        "Parses stored Nmap XML and merges observations by host address. Open "
        "observations win over closed ones. A scan whose raw file is missing or "
        "unparseable is reported in its scan entry with a parse_error."
    ),
)
async def get_recon(
    assessment_id: int,
    db: DbSession,
    user: CurrentUser,
    settings: Settings = Depends(get_settings),
) -> ReconOut:
    assessment = await get_assessment_or_404(db, assessment_id)
    return await build_recon(db, settings, assessment)
