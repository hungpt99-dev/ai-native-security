"""Monitoring API: platform health and the unified security overview."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import CurrentPrincipal
from app.database.session import get_db
from app.modules.monitoring import service

router = APIRouter(prefix="/monitoring", tags=["monitoring"])


@router.get("/health")
def monitoring_health(
    db: Annotated[Session, Depends(get_db)], principal: CurrentPrincipal
) -> dict[str, Any]:
    """Evidence-based health for every continuous control."""
    return service.health(db)


@router.get("/overview")
def monitoring_overview(
    db: Annotated[Session, Depends(get_db)], principal: CurrentPrincipal
) -> dict[str, Any]:
    """Unified posture: assets, findings, incidents, events, health."""
    return service.overview(db)
